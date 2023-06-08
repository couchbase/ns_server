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
	"runtime/debug"

	"golang.org/x/crypto/pbkdf2"

	"gocbutils"
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
	changePassword([]byte) error
	getPasswordState() string
	getSecret() *secret
	setSecret(*secret) error
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
	passwordSource    string
	lockkey           []byte // derived from password
	isDefaultPassword bool   // true if the password is default (empty)
	keysInFile
}

type EncryptionServiceSettings struct {
	KeyStorageType     string                 `json:"keyStorageType"`
	KeyStorageSettings map[string]interface{} `json:"keyStorageSettings"`
}

type Config struct {
	EncryptionSettings EncryptionServiceSettings `json:"encryptionService"`
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
	default:
		panic(fmt.Sprintf("Unknown command %v", command))
	}
}

func (s *encryptionService) cmdGetState() {
	replySuccessWithData([]byte(s.encryptionKeys.getPasswordState()))
}

func (s *encryptionService) cmdInit(password []byte) {
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

func initEncryptionKeys(config *Config, password []byte) (secretIface, error) {
	if config.EncryptionSettings.KeyStorageType == "file" {
		settings := config.EncryptionSettings.KeyStorageSettings
		return initKeysFromFile(settings, password)
	}

	return nil, errors.New(fmt.Sprintf(
		"unknown encryption service key storage type: %s",
		config.EncryptionSettings.KeyStorageType))
}

func initKeysFromFile(settings map[string]interface{},
	password []byte) (secretIface, error) {
	datakeyFile := settings["path"].(string)

	encryptDatakey := (settings["encryptWithPassword"] == true)

	if !encryptDatakey {
		return &keysInFile{filePath: datakeyFile, secret: secret{}}, nil
	}

	passwordSource := settings["passwordSource"].(string)
	var passwordToUse []byte
	if passwordSource == "env" {
		pwdSettings, ok := settings["passwordSettings"].(map[string]interface{})
		if !ok {
			return nil, errors.New("passwordSettings are missing in config")
		}

		envName, found := pwdSettings["envName"].(string)
		if !found {
			return nil, errors.New("envName is missing in config")
		}
		passwordToUse = []byte(os.Getenv(envName))
		if len(passwordToUse) == 0 && len(password) > 0 {
			passwordToUse = password
		}
	} else {
		return nil, errors.New(fmt.Sprintf("unknown password source: %s",
			passwordSource))
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
	if !s.initialized {
		panic("Password was not set")
	}
	err := s.encryptionKeys.changePassword(data)
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
	key := s.encryptionKeys.getSecret().key
	err := saveKeys(s.encryptionKeys, key, nil)
	if err != nil {
		replyError(err.Error())
		return
	}
	replySuccess()
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

func (keys *keysInFile) changePassword(password []byte) error {
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

func (keys *keysInEncryptedFile) changePassword(password []byte) error {
	key := keys.keysInFile.secret.key
	backupKey := keys.keysInFile.secret.backupKey
	oldLockkey := keys.lockkey
	keys.lockkey = generateLockKey(password)
	err := saveKeys(keys, key, backupKey)
	if err != nil {
		keys.lockkey = oldLockkey
		return err
	}
	keys.isDefaultPassword = (len(password) == 0)
	return nil
}

func (keys *keysInEncryptedFile) getPasswordState() string {
	if keys.isDefaultPassword {
		return "default"
	}
	return "user_configured"
}

// Other functions:

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
	log_dbg("using tmp file %s when writing to %s", tmpfile.Name(), path)
	if err != nil {
		return err
	}

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
