// @author Couchbase <info@couchbase.com>
// @copyright 2016-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"

	"golang.org/x/crypto/pbkdf2"

	"context"
	"encoding/base64"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/couchbase/ns_server/deps/gocode/awsutils"
	"github.com/couchbase/ns_server/deps/gocode/gocbutils"
)

const keySize = 32
const nIterations = 4096

var hmacFun = sha1.New

var salt = [8]byte{20, 183, 239, 38, 44, 214, 22, 141}
var emptyString = []byte("")

type encryptionService struct {
	initialized    bool
	reader         *bufio.Reader
	configPath     string
	config         *Config
	encryptionKeys secretIface
}

var ErrKeysDoNotExist = errors.New("keys do not exist")
var ErrWrongPassword = errors.New("wrong password")

type secretIface interface {
	read() error
	remove() error
	changePassword([]byte, map[string]interface{}) error
	getPasswordState() string
	getSecret() *secret
	setSecret(*secret) error
	getStorageId() string
	sameSettings(interface{}) bool
}

type secret struct {
	key       []byte // secret itself
	backupKey []byte // backup secret (used for decryption during rotation)
}

type keysInFile struct {
	filePath string
	secret
}

type keysInEncryptedFile struct {
	passwordSource    string // implicitly used by sameSettings (deepEqual)
	lockkey           []byte // derived from password
	isDefaultPassword bool   // true if the password is default (empty)
	keysInFile
}

type keysViaScript struct {
	writeCmd     string
	readCmd      string
	deleteCmd    string
	cmdTimeoutMs int
	secret
}

type EncryptionServiceSettings struct {
	KeyStorageType     string                 `json:"keyStorageType"`
	KeyStorageSettings map[string]interface{} `json:"keyStorageSettings"`
}

type Config struct {
	EncryptionSettings EncryptionServiceSettings `json:"encryptionService"`
	StoredKeyConfigs   []storedKeyConfig         `json:"storedKeys"`
}

// Stored keys structs and interfaces:

// Configuration for stored keys, describes where to store keys, and what
// kind of key should encrypt it. It is read from main gosecrets config.
// Typical configuration can have two kinds of keys:
// [{"kind": "dek", "path": "/path/to/dek", "encryptByKind": "kek"},
//  {"kind": "kek", "path": "/path/to/kek", "encryptByKind": "encryptionService"}]

type storedKeyConfig struct {
	KeyKind       string `json:"kind"`
	Path          string `json:"path"`
	EncryptByKind string `json:"encryptByKind"`
}

// Low level interface that all kinds of stored keys should support
type storedKeyIface interface {
	name() string
	needRewrite(*storedKeyConfig) bool
	encryptMe(*storedKeysCtx) error
	decryptMe(*storedKeysCtx) error
	encryptData([]byte) ([]byte, error)
	decryptData([]byte) ([]byte, error)
	marshal() (storedKeyType, []byte, error)
	unmarshal(json.RawMessage) error
	usesSecretManagementKey() bool
}

// Struct for marshalling/unmarshalling of a generic stored key
type storedKeyJson struct {
	Type storedKeyType   `json:"type"`
	Raw  json.RawMessage `json:"keyData"`
}

type storedKeyType string

const (
	rawAESGCMKey storedKeyType = "raw-aes-gcm"
	awskmKey     storedKeyType = "awskm"
)

// Struct for marshalling/unmarshalling of a raw aes-gcm stored key
type rawAesGcmStoredKeyJson struct {
	Name              string `json:"name"`
	KeyKind           string `json:"kind"`
	SealedKeyData     []byte `json:"sealedKeyData"`
	EncryptedByKind   string `json:"encryptedByKind"`
	EncryptionKeyName string `json:"encryptionKeyName"`
}

// Struct represents raw aes-gcm stored key
type rawAesGcmStoredKey struct {
	Name              string
	Kind              string
	DecryptedKey      []byte
	EncryptedKey      []byte
	EncryptedByKind   string
	EncryptionKeyName string
}

type awsStoredKey struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	KeyArn     string `json:"keyArn"`
	Region     string `json:"region"`
	ConfigFile string `json:"configFile"`
	CredsFile  string `json:"credsFile"`
	Profile    string `json:"profile"`
	UseIMDS    bool   `jspn:"useIMDS"`
}

type storedKeysCtx struct {
	storedKeyConfigs           []storedKeyConfig
	encryptionServiceKey       []byte
	backupEncryptionServiceKey []byte
}

type readKeyReply struct {
	Type string          `json:"type"`
	Info json.RawMessage `json:"info"`
}

type readKeyAesKeyResponse struct {
	Key             string `json:"key"`
	EncryptionKeyId string `json:"encryptionKeyId"`
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			log_dbg("panic occurred: %v\n%s", err, string(debug.Stack()))
			panic(err)
		}
	}()

	gocbutils.LimitCPUThreads()

	var configPath string

	flag.StringVar(&configPath, "config", "", "path to configuration file")
	flag.Parse()

	config, err := readCfg(configPath)

	if err != nil {
		panic(err.Error())
	}

	s := &encryptionService{
		reader:     bufio.NewReader(os.Stdin),
		configPath: configPath,
		config:     config,
	}

	for {
		s.processCommand()
	}
}

func (s *encryptionService) readCommand() (byte, []byte) {
	var size uint32
	err := binary.Read(s.reader, binary.BigEndian, &size)
	if err == io.EOF {
		// parent died. close normally
		os.Exit(0)
	}
	if err != nil {
		reportReadError(err)
	}
	if size < 1 {
		panic("Command is too short")
	}
	command, err := s.reader.ReadByte()
	if err != nil {
		reportReadError(err)
	}
	if size == 1 {
		return command, nil
	}

	buf := make([]byte, size-1)
	_, err = io.ReadFull(s.reader, buf)
	if err != nil {
		reportReadError(err)
	}
	return command, buf
}

func reportReadError(err error) {
	panic(fmt.Sprintf("Error reading input %v", err))
}

func doReply(data []byte) {
	err := binary.Write(os.Stdout, binary.BigEndian, uint32(len(data)))
	if err != nil {
		panic(fmt.Sprintf("Error writing data %v", err))
	}
	os.Stdout.Write(data)
}

func replySuccessWithData(data []byte) {
	doReply(append([]byte{'S'}, data...))
}

func replySuccess() {
	doReply([]byte{'S'})
}

func replyError(error string) {
	doReply([]byte("E" + error))
}

func encodeKey(key []byte) []byte {
	if key == nil {
		return []byte{0}
	}
	return append([]byte{byte(len(key))}, key...)
}

func combineDataKeys(key1, key2 []byte) []byte {
	return append(encodeKey(key1), encodeKey(key2)...)
}

func (s *encryptionService) processCommand() {
	command, data := s.readCommand()

	switch command {
	case 1:
		s.cmdInit(data)
	case 2:
		s.cmdGetKeyRef()
	case 3:
		s.cmdEncrypt(data)
	case 4:
		s.cmdDecrypt(data)
	case 5:
		s.cmdChangePassword(data)
	case 6:
		s.cmdRotateDataKey()
	case 7:
		s.cmdClearBackupKey(data)
	case 8:
		s.cmdGetState()
	case 9:
		s.cmdReloadConfig(data)
	case 10:
		s.cmdCopySecrets(data)
	case 11:
		s.cmdCleanupSecrets(data)
	case 12:
		s.cmdStoreKey(data)
	case 13:
		s.cmdEncryptWithKey(data)
	case 14:
		s.cmdDecryptWithKey(data)
	case 15:
		s.cmdReadKey(data)
	default:
		panic(fmt.Sprintf("Unknown command %v", command))
	}
}

func (s *encryptionService) cmdGetState() {
	replySuccessWithData([]byte(s.encryptionKeys.getPasswordState()))
}

func (s *encryptionService) cmdInit(data []byte) {
	password := decodePass(data)
	var err error
	s.encryptionKeys, err = initEncryptionKeys(s.config, password)
	if err != nil {
		replyError(err.Error())
		return
	}

	err = readOrCreateKeys(s.encryptionKeys)
	if err != nil {
		replyError(err.Error())
		return
	}
	s.initialized = true
	replySuccess()
}

func decodePass(data []byte) []byte {
	var password []byte
	if data[0] == 1 {
		password = data[1:]
	}
	return password
}

func initEncryptionKeys(config *Config, password []byte) (secretIface, error) {
	if config.EncryptionSettings.KeyStorageType == "file" {
		settings := config.EncryptionSettings.KeyStorageSettings
		return initKeysFromFile(settings, password)
	} else if config.EncryptionSettings.KeyStorageType == "script" {
		settings := config.EncryptionSettings.KeyStorageSettings
		return initKeysViaScript(settings)
	}

	return nil, errors.New(fmt.Sprintf(
		"unknown encryption service key storage type: %s",
		config.EncryptionSettings.KeyStorageType))
}

func initKeysViaScript(settings map[string]interface{}) (*keysViaScript, error) {
	readCmd, found := settings["readCmd"].(string)
	if !found {
		return nil, errors.New(
			"readCmd is mandatory for this type of secret")
	}

	writeCmd, found := settings["writeCmd"].(string)
	if !found {
		writeCmd = ""
	}

	deleteCmd, found := settings["deleteCmd"].(string)
	if !found {
		deleteCmd = ""
	}

	timeoutMs, found := settings["cmdTimeoutMs"].(int)
	if !found {
		timeoutMs = 60000
	}

	return &keysViaScript{
		readCmd:      readCmd,
		writeCmd:     writeCmd,
		deleteCmd:    deleteCmd,
		cmdTimeoutMs: timeoutMs,
		secret:       secret{},
	}, nil
}

func initKeysFromFile(settings map[string]interface{},
	password []byte) (secretIface, error) {
	datakeyFile := settings["path"].(string)

	encryptDatakey := (settings["encryptWithPassword"] == true)

	if !encryptDatakey {
		return &keysInFile{filePath: datakeyFile, secret: secret{}}, nil
	}

	passwordSource, passwordToUse, err := initFilePassword(settings, password)
	if err != nil {
		return nil, err
	}

	lockkey := generateLockKey(passwordToUse)
	emptyPass := (len(passwordToUse) == 0)
	return &keysInEncryptedFile{
		passwordSource:    passwordSource,
		lockkey:           lockkey,
		isDefaultPassword: emptyPass,
		keysInFile: keysInFile{
			filePath: datakeyFile,
			secret:   secret{}},
	}, nil
}

func initFilePassword(
	settings map[string]interface{},
	password []byte) (string, []byte, error) {
	passwordSource := settings["passwordSource"].(string)
	var passwordToUse []byte
	if passwordSource == "env" {
		pwdSettings, ok := settings["passwordSettings"].(map[string]interface{})
		if !ok {
			return passwordSource, nil, errors.New(
				"passwordSettings are missing in config")
		}

		envName, found := pwdSettings["envName"].(string)
		if !found {
			return passwordSource, nil, errors.New(
				"envName is missing in config")
		}
		if password != nil {
			passwordToUse = password
		} else {
			passwordToUse = []byte(os.Getenv(envName))
		}
	} else if passwordSource == "script" {
		if password != nil {
			return passwordSource, nil, errors.New(
				"password is not nil")
		}
		pwdSettings, ok := settings["passwordSettings"].(map[string]interface{})
		if !ok {
			return passwordSource, nil, errors.New(
				"passwordSettings are missing in config")
		}
		passwordCmd, found := pwdSettings["passwordCmd"].(string)
		if !found {
			return passwordSource, nil, errors.New(
				"passwordCmd is missing in config")
		}
		cmdTimeoutMs, found := pwdSettings["cmdTimeoutMs"].(int)
		if !found {
			cmdTimeoutMs = 60000
		}
		output, err := callExternalScript(passwordCmd, cmdTimeoutMs)
		if err != nil {
			return passwordSource, nil, err
		}
		passwordToUse = []byte(output)
	} else {
		return passwordSource, nil, errors.New(
			fmt.Sprintf(
				"unknown password source: %s",
				passwordSource))
	}
	return passwordSource, passwordToUse, nil
}

func saveDatakey(datakeyFile string, dataKey, backupDataKey []byte) error {
	data := combineDataKeys(dataKey, backupDataKey)
	datakeyDir := filepath.Dir(datakeyFile)
	err := os.MkdirAll(datakeyDir, 0755)
	if err != nil {
		msg := fmt.Sprintf("failed to create dir for data key \"%s\": %s",
			datakeyDir, err.Error)
		return errors.New(msg)
	}
	err = atomicWriteFile(datakeyFile, data, 0640)
	if err != nil {
		msg := fmt.Sprintf("failed to write datakey file \"%s\": %s",
			datakeyFile, err.Error)
		return errors.New(msg)
	}
	return nil
}

func readDatakey(datakeyFile string) ([]byte, []byte, error) {
	data, err := os.ReadFile(datakeyFile)
	if os.IsNotExist(err) {
		log_dbg("file %s does not exist", datakeyFile)
		return nil, nil, ErrKeysDoNotExist
	} else if err != nil {
		msg := fmt.Sprintf("failed to read datakey file \"%s\": %s",
			datakeyFile, err)
		return nil, nil, errors.New(msg)
	}
	key, data := readField(data)
	backup, _ := readField(data)
	return key, backup, nil
}

func createRandomKey() []byte {
	dataKey := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, dataKey); err != nil {
		panic(err.Error())
	}
	return dataKey
}

func readField(b []byte) ([]byte, []byte) {
	size := b[0]
	return b[1 : size+1], b[size+1:]
}

// same as readField by the size is encoded by 4 byte uint
func readBigField(data []byte) ([]byte, []byte) {
	sizeBin := data[0:4]
	size := binary.BigEndian.Uint32(sizeBin)
	return data[4 : size+4], data[(size + 4):]
}

func (s *encryptionService) cmdGetKeyRef() {
	replySuccessWithData(s.encryptionKeys.getSecret().getRef())
}

func (s *encryptionService) cmdEncrypt(data []byte) {
	if !s.initialized {
		panic("Password was not set")
	}
	dataKey := s.encryptionKeys.getSecret().key
	replySuccessWithData(encrypt(dataKey, data))
}

func (s *encryptionService) cmdDecrypt(data []byte) {
	if !s.initialized {
		panic("Password was not set")
	}

	key := s.encryptionKeys.getSecret().key

	res, mainKeyErr := decrypt(key, data)
	if mainKeyErr == nil {
		replySuccessWithData(res)
		return
	}

	backupKey := s.encryptionKeys.getSecret().backupKey

	if backupKey == nil {
		replyError(
			fmt.Sprintf(
				"Unable to decrypt value using main key: %s",
				mainKeyErr.Error()))
		return
	}

	res, backupKeyErr := decrypt(backupKey, data)
	if backupKeyErr != nil {
		replyError(
			fmt.Sprintf(
				"Unable to decrypt value using main key: '%s' "+
					"and using backup key: '%s'",
				mainKeyErr.Error(),
				backupKeyErr.Error()))
		return
	}
	replySuccessWithData(res)
}

func (s *encryptionService) cmdChangePassword(data []byte) {
	password := decodePass(data)
	if !s.initialized {
		panic("Password was not set")
	}
	err := s.encryptionKeys.changePassword(
		password,
		s.config.EncryptionSettings.KeyStorageSettings)
	if err != nil {
		replyError(err.Error())
		return
	}
	replySuccess()
}

func (s *encryptionService) cmdRotateDataKey() {
	if !s.initialized {
		panic("Password was not set")
	}
	backupKey := s.encryptionKeys.getSecret().backupKey
	if backupKey != nil {
		replyError("Data key rotation is in progress")
		return
	}
	prevkey := s.encryptionKeys.getSecret().key
	newkey := createRandomKey()
	err := saveKeys(s.encryptionKeys, newkey, prevkey)
	if err != nil {
		replyError(err.Error())
		return
	}
	replySuccess()
}

func (s *encryptionService) cmdClearBackupKey(ref []byte) {
	backupKey := s.encryptionKeys.getSecret().backupKey
	if backupKey == nil {
		replySuccess()
		return
	}

	if !bytes.Equal(s.encryptionKeys.getSecret().getRef(), ref) {
		replyError("Key ref mismatch")
		return
	}
	ctx := &storedKeysCtx{
		storedKeyConfigs:           s.config.StoredKeyConfigs,
		encryptionServiceKey:       s.encryptionKeys.getSecret().key,
		backupEncryptionServiceKey: s.encryptionKeys.getSecret().backupKey,
	}
	err := reencryptStoredKeys(ctx)
	if err != nil {
		replyError(err.Error())
		return
	}
	key := s.encryptionKeys.getSecret().key
	err = saveKeys(s.encryptionKeys, key, nil)
	if err != nil {
		replyError(err.Error())
		return
	}
	replySuccess()
}

func (s *encryptionService) cmdReloadConfig(data []byte) {
	password := decodePass(data)
	newConfig, err := readCfg(s.configPath)
	if err != nil {
		replyError(err.Error())
		return
	}
	newEncryptionKeys, err := initEncryptionKeys(newConfig, password)
	if err != nil {
		replyError(err.Error())
		return
	}

	err = readOrCreateKeys(newEncryptionKeys)
	if err != nil {
		replyError(err.Error())
		return
	}
	s.encryptionKeys = newEncryptionKeys
	s.config = newConfig
	replySuccess()
}

func (s *encryptionService) cmdCopySecrets(newCfgBytes []byte) {
	newConfig, err := readCfgBytes(newCfgBytes)
	if err != nil {
		replyError(err.Error())
		return
	}
	newEncryptionKeys, err := initEncryptionKeys(newConfig, nil)
	if err != nil {
		replyError(err.Error())
		return
	}
	res, err := copySecret(s.encryptionKeys, newEncryptionKeys)
	if err != nil {
		replyError(err.Error())
		return
	}
	replySuccessWithData([]byte(res))
}

func (s *encryptionService) cmdCleanupSecrets(oldCfgBytes []byte) {
	oldConfig, err := readCfgBytes(oldCfgBytes)
	if err != nil {
		replyError(err.Error())
		return
	}
	oldKeys, err := initEncryptionKeys(oldConfig, nil)
	if err != nil {
		replyError(err.Error())
		return
	}
	// We absolutelly must not remove secrets that are currently in use
	if oldKeys.getStorageId() == s.encryptionKeys.getStorageId() {
		replyError(fmt.Sprintf(
			"Can't remove secret '%s' because it is being used",
			oldKeys.getStorageId()))
		return
	}
	log_dbg("trying to remove secret: %s", oldKeys.getStorageId())
	err = oldKeys.remove()
	if err != nil {
		replyError(err.Error())
		return
	}
	replySuccess()
}

func (s *encryptionService) cmdStoreKey(data []byte) {
	keyKind, data := readBigField(data)
	keyName, data := readBigField(data)
	keyType, data := readBigField(data)
	keyData, data := readBigField(data)
	isKeyDataEncryptedBin, data := readBigField(data)
	encryptionKeyNameBin, _ := readBigField(data)
	keyKindStr := string(keyKind)
	keyNameStr := string(keyName)
	keyTypeStr := string(keyType)
	encryptionKeyName := string(encryptionKeyNameBin)
	isKeyDataEncryptedStr := string(isKeyDataEncryptedBin)
	isKeyDataEncrypted := (isKeyDataEncryptedStr == "true")
	if isKeyDataEncryptedStr != "true" && isKeyDataEncryptedStr != "false" {
		replyError(fmt.Sprintf("invalid isKeyDataEncrypted param: %v", isKeyDataEncryptedBin))
		return
	}
	log_dbg("Received request to store key %s (kind: %s, type: %s, encrypted: %v, encryptionKey: %s) on disk",
		keyNameStr, keyKindStr, keyTypeStr, isKeyDataEncrypted, encryptionKeyName)
	keySettings, err := getStoredKeyConfig(keyKindStr, s.config.StoredKeyConfigs)
	if err != nil {
		replyError(err.Error())
		return
	}
	var keyInfo storedKeyIface
	if keyTypeStr == string(rawAESGCMKey) {
		rawKeyInfo := &rawAesGcmStoredKey{
			Name:              keyNameStr,
			Kind:              keyKindStr,
			EncryptionKeyName: encryptionKeyName,
		}
		if isKeyDataEncrypted {
			rawKeyInfo.EncryptedKey = keyData
			rawKeyInfo.EncryptedByKind = keySettings.EncryptByKind
		} else {
			rawKeyInfo.DecryptedKey = keyData
		}
		keyInfo = rawKeyInfo
	} else if keyTypeStr == string(awskmKey) {
		var awsk awsStoredKey
		err = json.Unmarshal(keyData, &awsk)
		if err != nil {
			replyError(fmt.Sprintf("invalid json: %v", keyData))
			return
		}
		awsk.Name = keyNameStr
		awsk.Kind = keyKindStr
		keyInfo = &awsk
	} else {
		replyError(fmt.Sprintf("unknown type: %s", keyTypeStr))
		return
	}

	ctx := &storedKeysCtx{
		storedKeyConfigs:           s.config.StoredKeyConfigs,
		encryptionServiceKey:       s.encryptionKeys.getSecret().key,
		backupEncryptionServiceKey: s.encryptionKeys.getSecret().backupKey,
	}

	if !keyInfo.needRewrite(keySettings) {
		// key is already on disk and encrypted with the correct key
		log_dbg("Key %s is already on disk, will do nothing", keyNameStr)
		replySuccess()
		return
	}

	err = keyInfo.encryptMe(ctx)
	if err != nil {
		replyError(err.Error())
		return
	}

	err = writeKeyToDisk(keyInfo, keySettings)
	if err != nil {
		replyError(err.Error())
		return
	}

	replySuccess()
}

func (s *encryptionService) cmdReadKey(data []byte) {
	keyKind, data := readBigField(data)
	keyName, data := readBigField(data)
	keyKindStr := string(keyKind)
	keyNameStr := string(keyName)
	keySettings, err := getStoredKeyConfig(keyKindStr, s.config.StoredKeyConfigs)
	if err != nil {
		replyError(err.Error())
		return
	}
	keyIface, err := readKeyRaw(keySettings, keyNameStr)
	if err != nil {
		replyError(err.Error())
		return
	}
	ctx := &storedKeysCtx{
		storedKeyConfigs:           s.config.StoredKeyConfigs,
		encryptionServiceKey:       s.encryptionKeys.getSecret().key,
		backupEncryptionServiceKey: s.encryptionKeys.getSecret().backupKey,
	}
	err = keyIface.decryptMe(ctx)
	if err != nil {
		replyError(err.Error())
		return
	}
	rawKey, ok := keyIface.(*rawAesGcmStoredKey)
	if !ok {
		replyError("key type not supported")
		return
	}
	keyBase64 := base64.StdEncoding.EncodeToString(rawKey.DecryptedKey)
	keyToMarshal := readKeyAesKeyResponse{
		Key:             keyBase64,
		EncryptionKeyId: rawKey.EncryptionKeyName,
	}
	keyJson, err := json.Marshal(keyToMarshal)
	if err != nil {
		replyError(fmt.Sprintf("failed to marshal key: %s", err.Error()))
		return
	}
	replyToMarshal := readKeyReply{
		Type: string(rawAESGCMKey),
		Info: keyJson,
	}
	replyJson, err := json.Marshal(replyToMarshal)
	if err != nil {
		replyError(fmt.Sprintf("failed to marshal reply: %s", err.Error()))
		return
	}
	replySuccessWithData(replyJson)
}

func (s *encryptionService) cmdEncryptWithKey(data []byte) {
	toEncrypt, data := readBigField(data)
	keyKindBin, data := readBigField(data)
	keyNameBin, data := readBigField(data)
	keyKind := string(keyKindBin)
	keyName := string(keyNameBin)

	ctx := &storedKeysCtx{
		storedKeyConfigs:           s.config.StoredKeyConfigs,
		encryptionServiceKey:       s.encryptionKeys.getSecret().key,
		backupEncryptionServiceKey: s.encryptionKeys.getSecret().backupKey,
	}
	encryptedData, err := encryptWithKey(keyKind, keyName, toEncrypt, ctx)
	if err != nil {
		replyError(err.Error())
		return
	}
	replySuccessWithData(encryptedData)
}

func (s *encryptionService) cmdDecryptWithKey(data []byte) {
	toDecrypt, data := readBigField(data)
	keyKindBin, data := readBigField(data)
	keyNameBin, data := readBigField(data)
	keyKind := string(keyKindBin)
	keyName := string(keyNameBin)

	ctx := &storedKeysCtx{
		storedKeyConfigs:           s.config.StoredKeyConfigs,
		encryptionServiceKey:       s.encryptionKeys.getSecret().key,
		backupEncryptionServiceKey: s.encryptionKeys.getSecret().backupKey,
	}
	decryptedData, err := decryptWithKey(keyKind, keyName, toDecrypt, ctx)
	if err != nil {
		replyError(err.Error())
		return
	}
	replySuccessWithData(decryptedData)
}

func generateLockKey(password []byte) []byte {
	return pbkdf2.Key(password, salt[:], nIterations, keySize, hmacFun)
}

func encrypt(key []byte, data []byte) []byte {
	encrypted := aesgcmEncrypt(key, data)
	return append([]byte{0}, encrypted...)
}

func decrypt(key []byte, data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, errors.New("ciphertext is too short")
	}
	if data[0] != 0 {
		return nil, errors.New("unsupported cipher")
	}
	return aesgcmDecrypt(key, data[1:len(data)])
}

func aesgcmEncrypt(key []byte, data []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	return aesgcm.Seal(nonce[:aesgcm.NonceSize()], nonce, data, nil)
}

func aesgcmDecrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	if len(data) < aesgcm.NonceSize() {
		return nil, errors.New("ciphertext is too short")
	}
	nonce := data[:aesgcm.NonceSize()]
	data = data[aesgcm.NonceSize():]

	return aesgcm.Open(nil, nonce, data, nil)
}

func log_dbg(str string, args ...interface{}) {
	doReply([]byte("L" + fmt.Sprintf(str, args...)))
}

// Implementation of secretIface for keysInFile

func (keys *keysInFile) setSecret(s *secret) error {
	err := saveDatakey(keys.filePath, s.key, s.backupKey)
	if err != nil {
		return err
	}
	copySecretStruct(s, &keys.secret)
	return nil
}

func (keys *keysInFile) read() error {
	key, backupKey, err := readDatakey(keys.filePath)
	if err != nil {
		return err
	}
	if len(backupKey) > 0 {
		keys.secret.backupKey = backupKey
	} else {
		keys.secret.backupKey = nil
	}
	keys.secret.key = key
	log_dbg("read encryption keys from '%s' (%d byte main key, "+
		"and %d byte backup key)", keys.filePath, len(key), len(backupKey))
	return nil
}

func (keys *keysInFile) remove() error {
	return os.Remove(keys.filePath)
}

func (keys *keysInFile) changePassword(
	password []byte,
	settings map[string]interface{}) error {
	return errors.New("not supported")
}

func (keys *keysInFile) getPasswordState() string {
	return "password_not_used"
}

func (secret *secret) getRef() []byte {
	res := sha512.Sum512(combineDataKeys(secret.key, secret.backupKey))
	return res[:]
}

func (sec *secret) getSecret() *secret {
	return sec
}

func (keys *keysInFile) getStorageId() string {
	return "file:" + keys.filePath
}

func (keys *keysInFile) sameSettings(param interface{}) bool {
	keys2, ok := param.(*keysInFile)
	if !ok {
		return false
	}
	oldsecret := keys2.secret
	keys2.secret = keys.secret
	defer func() {
		keys2.secret = oldsecret
	}()
	return reflect.DeepEqual(keys, keys2)
}

// Implementation of secretIface for keysInEncryptedFile

func (keys *keysInEncryptedFile) setSecret(s *secret) error {
	newSecret := secret{}
	copySecretStruct(s, &newSecret)
	encryptedKey := encrypt(keys.lockkey, newSecret.key)
	var encryptedBackup []byte
	if newSecret.backupKey == nil {
		encryptedBackup = nil
	} else {
		encryptedBackup = encrypt(keys.lockkey, newSecret.backupKey)
	}
	err := saveDatakey(keys.filePath, encryptedKey, encryptedBackup)
	if err != nil {
		return err
	}
	keys.keysInFile.secret = newSecret
	return nil
}

func (keys *keysInEncryptedFile) read() error {
	encryptedKey, encryptedBackup, err := readDatakey(keys.filePath)
	if err != nil {
		return err
	}

	key, err := decrypt(keys.lockkey, encryptedKey)
	if err != nil {
		return errors.New(fmt.Sprintf("key decrypt failed: %s",
			err.Error()))
	}
	keys.secret.key = key

	if len(encryptedBackup) > 0 {
		backup, err := decrypt(keys.lockkey, encryptedBackup)
		if err != nil {
			return errors.New(fmt.Sprintf("backup key decrypt failed: %s",
				err.Error()))
		}
		keys.secret.backupKey = backup
	} else {
		keys.secret.backupKey = nil
	}

	log_dbg("read encryption keys from '%s' (%d byte main key, "+
		"and %d byte backup key)",
		keys.filePath, len(encryptedKey), len(encryptedBackup))
	return nil
}

func (keys *keysInEncryptedFile) changePassword(
	password []byte,
	settings map[string]interface{}) error {
	_, passwordToUse, err := initFilePassword(settings, password)
	if err != nil {
		return err
	}
	oldLockkey := keys.lockkey
	keys.lockkey = generateLockKey(passwordToUse)
	err = keys.setSecret(keys.getSecret())
	if err != nil {
		keys.lockkey = oldLockkey
		return err
	}
	keys.isDefaultPassword = (len(passwordToUse) == 0)
	return nil
}

func (keys *keysInEncryptedFile) getPasswordState() string {
	if keys.isDefaultPassword {
		return "default"
	}
	return "user_configured"
}

func (keys *keysInEncryptedFile) sameSettings(param interface{}) bool {
	keys2, ok := param.(*keysInEncryptedFile)
	if !ok {
		return false
	}
	oldsecret := keys2.secret
	oldLockkey := keys2.lockkey
	oldIsDefaultPass := keys2.isDefaultPassword
	keys2.secret = keys.secret
	keys2.lockkey = keys.lockkey
	keys2.isDefaultPassword = keys.isDefaultPassword
	defer func() {
		keys2.secret = oldsecret
		keys2.lockkey = oldLockkey
		keys2.isDefaultPassword = oldIsDefaultPass
	}()
	return reflect.DeepEqual(keys, keys2)
}

// Implementation of secretIface for keysViaScript

func (keys *keysViaScript) setSecret(s *secret) error {
	keyBase64 := base64.StdEncoding.EncodeToString(s.getSecret().key)
	backupBase64 := base64.StdEncoding.EncodeToString(s.getSecret().backupKey)
	cmd := strings.Join([]string{keys.writeCmd, keyBase64, backupBase64}, " ")
	_, err := callExternalScript(cmd, keys.cmdTimeoutMs)
	if err != nil {
		return err
	}
	copySecretStruct(s, &keys.secret)
	return nil
}

func (keys *keysViaScript) read() error {
	res, err := callExternalScript(keys.readCmd, keys.cmdTimeoutMs)
	if err != nil {
		return err
	}
	keysTokens := strings.Fields(res)
	var backup []byte
	if len(keysTokens) == 2 {
		backup, err = base64.StdEncoding.DecodeString(keysTokens[1])
		if err != nil {
			return errors.New(
				fmt.Sprintf(
					"Failed to decode backup key "+
						"(expected to be base64 encoded): %s",
					err.Error()))
		}
	} else if len(keysTokens) == 1 {
		backup = nil
	} else if len(keysTokens) == 0 {
		return ErrKeysDoNotExist
	} else {
		return errors.New(
			fmt.Sprintf(
				"Unexpected number of keys (%v) returned by %s",
				len(keysTokens), keys.readCmd))
	}
	key, err := base64.StdEncoding.DecodeString(keysTokens[0])
	if err != nil {
		return errors.New(
			fmt.Sprintf(
				"Failed to decode key (expected to be base64 encoded): %s",
				err.Error()))
	}
	keys.secret.key = key
	keys.secret.backupKey = backup
	log_dbg("read keys via script '%s'", keys.readCmd)
	return nil
}

func (keys *keysViaScript) remove() error {
	_, err := callExternalScript(keys.deleteCmd, keys.cmdTimeoutMs)
	if err != nil {
		return err
	}
	return nil
}

func (keys *keysViaScript) changePassword(
	password []byte,
	settings map[string]interface{}) error {
	return errors.New("not supported")
}

func (keys *keysViaScript) getPasswordState() string {
	return "password_not_used"
}

func (keys *keysViaScript) getStorageId() string {
	return "script:" + keys.writeCmd
}

func (keys *keysViaScript) sameSettings(param interface{}) bool {
	keys2, ok := param.(*keysViaScript)
	if !ok {
		return false
	}
	oldsecret := keys2.secret
	keys2.secret = keys.secret
	defer func() {
		keys2.secret = oldsecret
	}()
	return reflect.DeepEqual(keys, keys2)
}

// Other functions:

func copySecret(from, to secretIface) (string, error) {
	log_dbg("Trying to copy a secret\nOld cfg type: %v\nNew cfg type: %v",
		reflect.TypeOf(from), reflect.TypeOf(to))

	if from.sameSettings(to) {
		log_dbg("same secret configs, nothing to do")
		return "same", nil
	}

	// Here we are trying to make sure we are not corrupting existing secrets
	// by creating secrets copy for new config.
	// For example, if new and old config use the same file on disk, we might
	// corrupt old secret file by writing to the same file using new config.
	err := to.read()

	if err != nil {
		if !errors.Is(err, ErrKeysDoNotExist) {
			// We can't continue even if it is caused by a different password
			// because the copy will basically change the password for
			// the secret then, and rollback will not work in case of a problem
			return "", errors.New(
				fmt.Sprintf(
					"Secret already exists but it can't be read (%s)",
					err.Error()))
		}
		log_dbg("New secret doesn't exist")
	} else {
		// Even if new config uses the same storage for this secret,
		// it should be safe to overwrite it using new config
		// because it should not really change the file (but we still
		// want to do the writing, because we want to test that it
		// works)
		secretsMatch := bytes.Equal(from.getSecret().key, to.getSecret().key) &&
			bytes.Equal(from.getSecret().backupKey, to.getSecret().backupKey)
		if !secretsMatch {
			log_dbg(
				"New secret already exists and it doesn't " +
					"match the secret that is in use")
			oldStorage := from.getStorageId()
			newStorage := to.getStorageId()
			if oldStorage == newStorage {
				return "", errors.New(
					fmt.Sprintf(
						"Can't use exactly same storage for secret "+
							"(old storage: %s, new storage: %s)",
						oldStorage, newStorage))
			}
			// that's ok, new and old configs use different storages
			// for secrets, so we will not overwrite existing secret
			// if we save new secret here
		} else {
			log_dbg("New secret already exists and it matches" +
				"the secret that is in use")
		}
	}
	err = to.setSecret(from.getSecret())
	if err != nil {
		return "", err
	}
	// just making sure it is readable
	err = to.read()
	if err != nil {
		log_dbg("Failed to read the secret after writing: %s", err.Error())
		return "", err
	}
	return "copied", nil
}

func saveKeys(keys secretIface, key, backup []byte) error {
	newSecret := secret{key: key, backupKey: backup}
	return keys.setSecret(&newSecret)
}

// Note: keys must be a pointer to a struct
func readOrCreateKeys(keys secretIface) error {
	err := keys.read()
	if errors.Is(err, ErrKeysDoNotExist) {
		log_dbg("Generating secret")
		key := createRandomKey()
		return saveKeys(keys, key, nil)
	}
	return err
}

func atomicWriteFile(path string, binary []byte, perm fs.FileMode) (err error) {
	tmpfile, err := ioutil.TempFile(
		filepath.Dir(path), filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	log_dbg("using tmp file %s when writing to %s", tmpfile.Name(), path)

	defer func() {
		if err != nil {
			tmpfile.Close()
			os.Remove(tmpfile.Name())
		}
	}()

	_, err = tmpfile.Write(binary)
	if err != nil {
		return err
	}

	if err := tmpfile.Chmod(perm); err != nil {
		return err
	}

	tmpfile.Sync()

	if err := tmpfile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpfile.Name(), path)
}

func readCfg(configPath string) (*Config, error) {
	configBytes, err := os.ReadFile(configPath)

	if err != nil {
		return nil, errors.New(
			fmt.Sprintf("failed to read config file (\"%s\"): %s",
				configPath, err))
	}
	return readCfgBytes(configBytes)
}

func readCfgBytes(configBytes []byte) (*Config, error) {
	log_dbg("parsing config: \n%s", string(configBytes))
	var config Config
	err := json.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, errors.New(
			fmt.Sprintf(
				"failed to parse config file: %s\n%s",
				err, configBytes))
	}

	return &config, nil
}

func copySecretStruct(from *secret, to *secret) {
	to.key = make([]byte, len(from.key))
	copy(to.key, from.key)
	if from.backupKey == nil {
		to.backupKey = nil
	} else {
		to.backupKey = make([]byte, len(from.backupKey))
		copy(to.backupKey, from.backupKey)
	}
}

func callExternalScript(cmdStr string, timeoutMs int) (string, error) {
	log_dbg("Calling cmd '%s'... ", cmdStr)
	cmdSlice := strings.Fields(cmdStr)
	timeoutDuration := time.Duration(timeoutMs * 1000000)
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdSlice[0], cmdSlice[1:]...)
	var stdoutbuf, stderrbuf bytes.Buffer
	cmd.Stdout = &stdoutbuf
	cmd.Stderr = &stderrbuf
	err := cmd.Run()
	res := stdoutbuf.String()
	if err != nil {
		return res, errors.New(fmt.Sprintf(
			"Command '%s' finished with error(error: '%v', stderr: '%s')",
			cmdStr, err.Error(), stderrbuf.String()))
	}
	return res, nil
}

// Stored keys managenement functions

func writeKeyToDisk(keyIface storedKeyIface, keySettings *storedKeyConfig) error {
	keytype, data, err := keyIface.marshal()
	if err != nil {
		return err
	}
	finalData, err := json.Marshal(storedKeyJson{Type: keytype, Raw: data})
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to marshal key %s: %s", keyIface.name(), err.Error()))
	}

	keyPath := storedKeyPath(keySettings, keyIface.name())
	log_dbg("Writing %s (%s) to file %s", keyIface.name(), keySettings.KeyKind, keyPath)
	keyDir := filepath.Dir(keyPath)
	err = os.MkdirAll(keyDir, 0755)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to create dir for file %s: %s", keyPath, err.Error()))
	}
	err = atomicWriteFile(keyPath, finalData, 0640)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to write key %s to file %s: %s", keyIface.name(), keyPath, err.Error()))
	}
	return nil
}

func encryptWithKey(keyKind, keyName string, data []byte, ctx *storedKeysCtx) ([]byte, error) {
	keySettings, err := getStoredKeyConfig(keyKind, ctx.storedKeyConfigs)
	if err != nil {
		return nil, err
	}
	keyIface, err := readKeyRaw(keySettings, keyName)
	if err != nil {
		return nil, err
	}
	err = keyIface.decryptMe(ctx)
	if err != nil {
		return nil, err
	}
	return keyIface.encryptData(data)
}

func decryptWithKey(keyKind, keyName string, data []byte, ctx *storedKeysCtx) ([]byte, error) {
	keySettings, err := getStoredKeyConfig(keyKind, ctx.storedKeyConfigs)
	if err != nil {
		return nil, err
	}
	keyIface, err := readKeyRaw(keySettings, keyName)
	if err != nil {
		return nil, err
	}
	err = keyIface.decryptMe(ctx)
	if err != nil {
		return nil, err
	}
	return keyIface.decryptData(data)
}

func getStoredKeyConfig(keyKind string, configs []storedKeyConfig) (*storedKeyConfig, error) {
	index := slices.IndexFunc(configs, func(c storedKeyConfig) bool { return c.KeyKind == keyKind })
	if index == -1 {
		return nil, errors.New(fmt.Sprintf("Failed to find key kind \"%s\" in config", keyKind))
	}
	return &configs[index], nil
}

func readKeyRaw(keySettings *storedKeyConfig, keyName string) (storedKeyIface, error) {
	path := storedKeyPath(keySettings, keyName)
	log_dbg("Reading key %s from file %s", keyName, path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to read key from file %s: %s", path, err.Error()))
	}
	var keyJson storedKeyJson
	err = json.Unmarshal(data, &keyJson)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Failed to unmarshal key from file %s: %s", path, err.Error()))
	}

	if keyJson.Type == rawAESGCMKey {
		var k rawAesGcmStoredKey
		k.unmarshal(keyJson.Raw)
		return &k, nil
	}

	if keyJson.Type == awskmKey {
		var k awsStoredKey
		k.unmarshal(keyJson.Raw)
		return &k, nil
	}

	return nil, errors.New(fmt.Sprintf("Unknown key type: %s", keyJson.Type))
}

func storedKeyPath(keySettings *storedKeyConfig, keyName string) string {
	return filepath.Join(keySettings.Path, keyName)
}

// Reencrypt keys that use secret management (SM) encryption key
// Needed for SM data key rotation
func reencryptStoredKeys(ctx *storedKeysCtx) error {
	for _, cfg := range ctx.storedKeyConfigs {
		if cfg.KeyKind != "kek" {
			continue
		}
		files, dirReadErr := os.ReadDir(cfg.Path)
		log_dbg("Will check if the following keys need reencryption: %v", files)
		if dirReadErr != nil {
			if os.IsNotExist(dirReadErr) {
				return nil
			}
		}
		errorsCounter := 0
		// Even in case of an error ReadDir can return files
		// Reencrypt everything we can
		if files != nil {
			for _, file := range files {
				keyName := file.Name()
				log_dbg("Maybe reencrypting key \"%s\"...", keyName)
				keyIface, err := readKeyRaw(&cfg, keyName)
				if err != nil {
					log_dbg(err.Error())
					errorsCounter++
					continue
				}
				if !keyIface.usesSecretManagementKey() {
					log_dbg("Skipping \"%s\", because it is not using secret management service", keyName)
				}
				err = keyIface.decryptMe(ctx)
				if err != nil {
					log_dbg(err.Error())
					errorsCounter++
					continue
				}
				err = keyIface.encryptMe(ctx)
				if err != nil {
					log_dbg(err.Error())
					errorsCounter++
					continue
				}
				err = writeKeyToDisk(keyIface, &cfg)
				if err != nil {
					log_dbg(err.Error())
					errorsCounter++
					continue
				}
			}
		}
		if dirReadErr != nil {
			return errors.New(fmt.Sprintf("Could not reencrypt keys because could not read dir \"%s\": %s", cfg.Path, dirReadErr.Error()))
		}
		if errorsCounter > 0 {
			return errors.New(fmt.Sprintf("Could not reencrypt some keys in \"%s\"", cfg.Path))
		}
	}
	return nil
}

// Implementation of storedKeyIface for raw keys

func (k *rawAesGcmStoredKey) name() string {
	return k.Name
}

func (k *rawAesGcmStoredKey) needRewrite(settings *storedKeyConfig) bool {
	keyIface, err := readKeyRaw(settings, k.Name)
	if err != nil {
		log_dbg("key %s read error: %s", k.Name, err.Error())
		return true
	}
	onDiskKey, ok := keyIface.(*rawAesGcmStoredKey)
	if !ok {
		log_dbg("key %s changed type, rewriting", k.Name)
		return true
	}
	return onDiskKey.EncryptedByKind != settings.EncryptByKind || onDiskKey.EncryptionKeyName != k.EncryptionKeyName
}

func (k *rawAesGcmStoredKey) encryptMe(ctx *storedKeysCtx) error {
	settings, err := getStoredKeyConfig(k.Kind, ctx.storedKeyConfigs)
	if err != nil {
		return err
	}
	if k.EncryptedKey != nil {
		reencryptNeeded := false
		// Seems like the key is already encrypted
		// Checking that we can decrypt it just in case
		log_dbg("Verifying encryption for key \"%s\"", k.Name)
		if k.usesSecretManagementKey() {
			_, err = decrypt(ctx.encryptionServiceKey, k.EncryptedKey)
			if err != nil {
				log_dbg("Failed to decrypt key using main data key: %s", err.Error())
				if ctx.backupEncryptionServiceKey != nil {
					decryptedKey, err2 := decrypt(ctx.backupEncryptionServiceKey, k.EncryptedKey)
					if err2 == nil {
						err = nil
						log_dbg("Decrypted using backup data key")
						reencryptNeeded = true
						k.DecryptedKey = decryptedKey
					} else {
						log_dbg("Failed to decrypt key using backup data key: %s", err2.Error())
					}
				} else {
					log_dbg("Backup key is not set")
				}
			}
		} else {
			_, err = decryptWithKey(k.EncryptedByKind, k.EncryptionKeyName, k.EncryptedKey, ctx)
		}
		if err != nil {
			return errors.New(fmt.Sprintf("key \"%s\" is already encrypted but encryption verification failed (could not decrypt): %s", k.Name, err.Error()))
		}
		if !reencryptNeeded {
			return nil
		}
	}
	if k.DecryptedKey == nil {
		return errors.New("key is empty")
	}
	k.EncryptedByKind = settings.EncryptByKind
	if k.usesSecretManagementKey() {
		// Encrypting with encryption service's data key
		log_dbg("Will use encryption service to encrypt key %s", k.Name)
		// Using encrypt instead of aesgcmEncrypt here
		// because we want to include encryption cipher (version
		// basically) information in the encrypted data for the case if
		// we want to change encryption cipher in future.
		// This doesn't apply to encryptWithKey, because that
		// information sits in the stored key (each stored key can be
		// used by one cipher only).
		k.EncryptedKey = encrypt(ctx.encryptionServiceKey, k.DecryptedKey)
		return nil
	}
	// Encrypting with another stored key (kek) that we will read from disk
	log_dbg("Will use key %s to encrypt key %s", k.EncryptionKeyName, k.Name)
	encryptedData, err := encryptWithKey(settings.EncryptByKind, k.EncryptionKeyName, k.DecryptedKey, ctx)
	if err != nil {
		return err
	}
	k.EncryptedKey = encryptedData
	return nil
}

func (k *rawAesGcmStoredKey) decryptMe(ctx *storedKeysCtx) error {
	if k.usesSecretManagementKey() {
		log_dbg("Will use encryption service to decrypt key %s", k.Name)
		decryptedData, err := decrypt(ctx.encryptionServiceKey, k.EncryptedKey)
		if err != nil {
			if ctx.backupEncryptionServiceKey != nil {
				decryptedData, err = decrypt(ctx.backupEncryptionServiceKey, k.EncryptedKey)
			}
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to decrypt key %s: %s", k.Name, err.Error()))
			}
		}
		k.DecryptedKey = decryptedData
		return nil
	}
	decryptedData, err := decryptWithKey(k.EncryptedByKind, k.EncryptionKeyName, k.EncryptedKey, ctx)
	if err != nil {
		return err
	}
	k.DecryptedKey = decryptedData
	return nil
}

func (k *rawAesGcmStoredKey) encryptData(data []byte) ([]byte, error) {
	if k.DecryptedKey == nil {
		return nil, errors.New("Can't encrypt because the key is encrypted")
	}
	return aesgcmEncrypt(k.DecryptedKey, data), nil
}

func (k *rawAesGcmStoredKey) decryptData(data []byte) ([]byte, error) {
	if k.DecryptedKey == nil {
		return nil, errors.New("Can't decrypt because the key is encrypted")
	}
	return aesgcmDecrypt(k.DecryptedKey, data)
}

func (k *rawAesGcmStoredKey) unmarshal(data json.RawMessage) error {
	var decoded rawAesGcmStoredKeyJson
	err := json.Unmarshal(data, &decoded)
	if err != nil {
		return errors.New(fmt.Sprintf("invalid raw key json: %s", err.Error()))
	}
	k.Name = decoded.Name
	k.Kind = decoded.KeyKind
	k.DecryptedKey = nil
	k.EncryptedKey = decoded.SealedKeyData
	k.EncryptedByKind = decoded.EncryptedByKind
	k.EncryptionKeyName = decoded.EncryptionKeyName
	return nil
}

func (k *rawAesGcmStoredKey) usesSecretManagementKey() bool {
	return k.EncryptionKeyName == "encryptionService"
}

func (k *rawAesGcmStoredKey) marshal() (storedKeyType, []byte, error) {
	if k.EncryptedKey == nil {
		return "", nil, errors.New(fmt.Sprintf("Cant' store key \"%s\" to disk because the key is not encrypted", k.Name))
	}
	data, err := json.Marshal(rawAesGcmStoredKeyJson{
		Name:              k.Name,
		KeyKind:           k.Kind,
		SealedKeyData:     k.EncryptedKey,
		EncryptedByKind:   k.EncryptedByKind,
		EncryptionKeyName: k.EncryptionKeyName})

	if err != nil {
		return "", nil, errors.New(fmt.Sprintf("Failed to marshal key %s: %s", k.Name, err.Error()))
	}
	return rawAESGCMKey, data, nil
}

// Implementation of storedKeyIface for aws keys
func (k *awsStoredKey) name() string {
	return k.Name
}

func (k *awsStoredKey) needRewrite(settings *storedKeyConfig) bool {
	// since we don't need to encrypt anything in this case, it seems like
	// it would be simpler to always rewrite it on disk
	return true
}

func (k *awsStoredKey) encryptMe(ctx *storedKeysCtx) error {
	// Nothing to encrypt here, configuration should contain no secrets
	return nil
}

func (k *awsStoredKey) decryptMe(ctx *storedKeysCtx) error {
	return nil
}

func (k *awsStoredKey) encryptData(data []byte) ([]byte, error) {
	opts := awsutils.AwsConfigOpts{
		Region:     k.Region,
		ConfigFile: k.ConfigFile,
		CredsFile:  k.CredsFile,
		Profile:    k.Profile,
		UseIMDS:    k.UseIMDS,
	}
	return awsutils.KmsEncryptData(k.KeyArn, data, opts)
}

func (k *awsStoredKey) decryptData(data []byte) ([]byte, error) {
	opts := awsutils.AwsConfigOpts{
		Region:     k.Region,
		ConfigFile: k.ConfigFile,
		CredsFile:  k.CredsFile,
		Profile:    k.Profile,
		UseIMDS:    k.UseIMDS,
	}
	return awsutils.KmsDecryptData(k.KeyArn, data, opts)
}

func (k *awsStoredKey) unmarshal(data json.RawMessage) error {
	err := json.Unmarshal(data, k)
	if err != nil {
		return errors.New(fmt.Sprintf("invalid raw key json: %s", err.Error()))
	}
	return nil
}

func (k *awsStoredKey) marshal() (storedKeyType, []byte, error) {
	data, err := json.Marshal(k)
	if err != nil {
		return "", nil, errors.New(fmt.Sprintf("Failed to marshal key %s: %s", k.Name, err.Error()))
	}
	return awskmKey, data, nil
}

func (k *awsStoredKey) usesSecretManagementKey() bool {
	return false
}
