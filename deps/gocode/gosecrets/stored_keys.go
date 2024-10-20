// @author Couchbase <info@couchbase.com>
// @copyright 2024-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/couchbase/ns_server/deps/gocode/awsutils"
	"os"
	"path/filepath"
	"reflect"
	"slices"
)

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
	kind() string
	needRewrite(*storedKeyConfig, *storedKeysCtx) (bool, error)
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
	kmipKey      storedKeyType = "kmip"
)

// Struct for marshalling/unmarshalling of a raw aes-gcm stored key
type rawAesGcmStoredKeyJson struct {
	Name              string `json:"name"`
	KeyKind           string `json:"kind"`
	SealedKeyData     []byte `json:"sealedKeyData"`
	EncryptedByKind   string `json:"encryptedByKind"`
	EncryptionKeyName string `json:"encryptionKeyName"`
	CreationTime      string `json:"creationTime"`
}

// Struct represents raw aes-gcm stored key
type rawAesGcmStoredKey struct {
	Name              string
	Kind              string
	DecryptedKey      []byte
	EncryptedKey      []byte
	EncryptedByKind   string
	EncryptionKeyName string
	CreationTime      string
}

type awsStoredKey struct {
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	KeyArn       string `json:"keyArn"`
	Region       string `json:"region"`
	ConfigFile   string `json:"configFile"`
	CredsFile    string `json:"credsFile"`
	Profile      string `json:"profile"`
	UseIMDS      bool   `jspn:"useIMDS"`
	CreationTime string `json:"creationTime"`
}

type kmipStoredKey struct {
	Name                string `json:"name"`
	Kind                string `json:"kind"`
	KmipId              string `json:"kmipId"`
	Host                string `json:"host"`
	Port                int    `json:"port"`
	EncryptionApproach  string `json:"encryptionApproach"`
	KeyCertPath         string `json:"keyCertPath"`
	EncryptedPassphrase []byte `json:"sealedPassphrase"`
	decryptedPassphrase []byte `json:"-"`
	EncryptionKeyName   string `json:"encryptionKeyName"`
	EncryptedByKind     string `json:"encryptedByKind"`
	CreationTime        string `json:"creationTime"`
}

type storedKeysCtx struct {
	storedKeyConfigs           []storedKeyConfig
	encryptionServiceKey       []byte
	backupEncryptionServiceKey []byte
	keysTouched                map[string]bool
}

type readKeyReply struct {
	Type string          `json:"type"`
	Info json.RawMessage `json:"info"`
}

type readKeyAesKeyResponse struct {
	Key             string `json:"key"`
	EncryptionKeyId string `json:"encryptionKeyId"`
	CreationTime    string `json:"creationTime"`
}

// Stored keys managenement functions

func store_key(name, kind, keyType string, isEncrypted bool, encryptionKeyName, creationTime string, otherData []byte, ctx *storedKeysCtx) error {
	keySettings, err := getStoredKeyConfig(kind, ctx.storedKeyConfigs)
	if err != nil {
		return err
	}
	var keyInfo storedKeyIface
	if keyType == string(rawAESGCMKey) {
		keyInfo = newAesGcmKey(name, kind, creationTime, encryptionKeyName, isEncrypted, otherData, keySettings)
	} else if keyType == string(awskmKey) {
		keyInfo, err = newAwsKey(name, kind, creationTime, otherData)
		if err != nil {
			return err
		}
	} else if keyType == string(kmipKey) {
		keyInfo, err = newKmipKey(name, kind, creationTime, encryptionKeyName, isEncrypted, otherData, keySettings)
		if err != nil {
			return err
		}
	} else {
		return errors.New(fmt.Sprintf("unknown type: %s", keyType))
	}

	shouldRewrite, err := keyInfo.needRewrite(keySettings, ctx)
	if err != nil {
		return err
	}
	if !shouldRewrite {
		// key is already on disk and encrypted with the correct key
		log_dbg("Key %s is already on disk, will do nothing", name)
		return nil
	}

	err = encryptKey(keyInfo, ctx)
	if err != nil {
		return err
	}

	err = writeKeyToDisk(keyInfo, keySettings)
	if err != nil {
		return err
	}

	return nil
}

func readKeyFromFile(path string, ctx *storedKeysCtx) (storedKeyIface, error) {
	keyIface, err := readKeyFromFileRaw(path)
	if err != nil {
		return nil, err
	}
	err = decryptKey(keyIface, ctx)
	if err != nil {
		return nil, err
	}
	return keyIface, nil
}

func readKey(name, kind string, ctx *storedKeysCtx) (storedKeyIface, error) {
	keySettings, err := getStoredKeyConfig(kind, ctx.storedKeyConfigs)
	if err != nil {
		return nil, err
	}
	keyIface, err := readKeyRaw(keySettings, name)
	if err != nil {
		return nil, err
	}
	err = decryptKey(keyIface, ctx)
	if err != nil {
		return nil, err
	}
	return keyIface, nil
}

func encryptKey(keyIface storedKeyIface, ctx *storedKeysCtx) error {
	// Mark it as in use, to make sure we don't try to use it for encryption
	// or decryption while we are encrypting or decrypting this key
	name := keyIface.name()
	ctx.keysTouched[name] = true
	defer delete(ctx.keysTouched, name)
	return keyIface.encryptMe(ctx)
}

func decryptKey(keyIface storedKeyIface, ctx *storedKeysCtx) error {
	// Mark it as in use, to make sure we don't try to use it for encryption
	// or decryption while we are encrypting or decrypting this key
	name := keyIface.name()
	ctx.keysTouched[name] = true
	defer delete(ctx.keysTouched, name)
	return keyIface.decryptMe(ctx)
}

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
	if _, ok := ctx.keysTouched[keyName]; ok {
		return nil, errors.New("Key encryption cycle")
	}
	keySettings, err := getStoredKeyConfig(keyKind, ctx.storedKeyConfigs)
	if err != nil {
		return nil, err
	}
	keyIface, err := readKeyRaw(keySettings, keyName)
	if err != nil {
		return nil, err
	}
	err = decryptKey(keyIface, ctx)
	if err != nil {
		return nil, err
	}
	return keyIface.encryptData(data)
}

func decryptWithKey(keyKind, keyName string, data []byte, ctx *storedKeysCtx) ([]byte, error) {
	if _, ok := ctx.keysTouched[keyName]; ok {
		return nil, errors.New("Key encryption loop")
	}

	keySettings, err := getStoredKeyConfig(keyKind, ctx.storedKeyConfigs)
	if err != nil {
		return nil, err
	}
	keyIface, err := readKeyRaw(keySettings, keyName)
	if err != nil {
		return nil, err
	}
	err = decryptKey(keyIface, ctx)
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
	return readKeyFromFileRaw(path)
}

func readKeyFromFileRaw(path string) (storedKeyIface, error) {
	log_dbg("Reading key from file %s", path)
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

	if keyJson.Type == kmipKey {
		var k kmipStoredKey
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
		// All keys but bucketDeks can be encrypted with
		// encryption_service
		if cfg.KeyKind == "bucketDek" {
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
				if keyName == "active_key" {
					continue
				}
				log_dbg("Maybe reencrypting key \"%s\"...", keyName)
				keyIface, err := readKeyRaw(&cfg, keyName)
				if err != nil {
					log_dbg(err.Error())
					errorsCounter++
					continue
				}
				if !keyIface.usesSecretManagementKey() {
					log_dbg("Skipping \"%s\", because it is not using secret management service", keyName)
					continue
				}
				err = decryptKey(keyIface, ctx)
				if err != nil {
					log_dbg(err.Error())
					errorsCounter++
					continue
				}
				err = encryptKey(keyIface, ctx)
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

// Helper function that is supposed to be used to encrypt data to be
// stored in the key json
func encryptKeyData(k storedKeyIface, data []byte, encryptionKeyName string, ctx *storedKeysCtx) ([]byte, string, error) {
	settings, err := getStoredKeyConfig(k.kind(), ctx.storedKeyConfigs)
	if err != nil {
		return nil, "", err
	}
	if data == nil {
		return nil, "", errors.New("encrypt data nil")
	}
	if k.usesSecretManagementKey() {
		// Encrypting with encryption service's data key
		log_dbg("Will use encryption service to encrypt key %s", k.name())
		// Using encrypt instead of aesgcmEncrypt here
		// because we want to include encryption cipher (version
		// basically) information in the encrypted data for the case if
		// we want to change encryption cipher in future.
		// This doesn't apply to encryptWithKey, because that
		// information sits in the stored key (each stored key can be
		// used by one cipher only).
		return encrypt(ctx.encryptionServiceKey, data), settings.EncryptByKind, nil
	}
	// Encrypting with another stored key (kek) that we will read from disk
	log_dbg("Will use key %s to encrypt key %s", encryptionKeyName, k.name())
	encryptedData, err := encryptWithKey(settings.EncryptByKind, encryptionKeyName, data, ctx)
	if err != nil {
		return nil, "", err
	}
	return encryptedData, settings.EncryptByKind, nil
}

// Helper function that is supposed to be used to decrypt data that is
// stored in the key json
// Returns decrypted data and if it needs to be reencrypted
func decryptKeyData(k storedKeyIface, data []byte, encryptedByKind, encryptionKeyName string, ctx *storedKeysCtx) ([]byte, bool, error) {
	if data == nil {
		return nil, false, errors.New("decrypt data is nil")
	}
	if k.usesSecretManagementKey() {
		log_dbg("Will use encryption service to decrypt key %s", k.name())
		decryptedData, err := decrypt(ctx.encryptionServiceKey, data)
		if err != nil {
			if ctx.backupEncryptionServiceKey != nil {
				log_dbg("Failed to decrypt key using main data key, will try backup key: %s", err.Error())
				decryptedData, err = decrypt(ctx.backupEncryptionServiceKey, data)
				if err != nil {
					log_dbg("Failed to decrypt key using backup data key: %s", err.Error())
					return nil, false, errors.New(fmt.Sprintf("Failed to decrypt key %s: %s", k.name(), err.Error()))
				}
			} else {
				log_dbg("Failed to decrypt key using main data key, and there is no backup key: %s", err.Error())
				return nil, false, errors.New(fmt.Sprintf("Failed to decrypt key %s: %s", k.name(), err.Error()))
			}
			log_dbg("Decrypted using backup data key")
			return decryptedData, true, nil
		}
		return decryptedData, false, nil
	}
	decryptedData, err := decryptWithKey(encryptedByKind, encryptionKeyName, data, ctx)
	if err != nil {
		return nil, false, err
	}
	return decryptedData, false, nil
}

// Implementation of storedKeyIface for raw keys

func newAesGcmKey(name, kind, creationTime, encryptionKeyName string, isEncrypted bool, data []byte, keySettings *storedKeyConfig) *rawAesGcmStoredKey {
	rawKeyInfo := &rawAesGcmStoredKey{
		Name:              name,
		Kind:              kind,
		EncryptionKeyName: encryptionKeyName,
		CreationTime:      creationTime,
	}
	if isEncrypted {
		rawKeyInfo.EncryptedKey = data
		rawKeyInfo.EncryptedByKind = keySettings.EncryptByKind
	} else {
		rawKeyInfo.DecryptedKey = data
	}
	return rawKeyInfo
}

func (k *rawAesGcmStoredKey) name() string {
	return k.Name
}

func (k *rawAesGcmStoredKey) kind() string {
	return k.Kind
}

func (k *rawAesGcmStoredKey) needRewrite(settings *storedKeyConfig, ctx *storedKeysCtx) (bool, error) {
	keyIface, err := readKeyRaw(settings, k.Name)
	if err != nil {
		log_dbg("key %s read error: %s", k.Name, err.Error())
		return true, nil
	}
	onDiskKey, ok := keyIface.(*rawAesGcmStoredKey)
	if !ok {
		log_dbg("key %s changed type, rewriting", k.Name)
		return true, nil
	}
	return onDiskKey.EncryptedByKind != settings.EncryptByKind || onDiskKey.EncryptionKeyName != k.EncryptionKeyName, nil
}

func (k *rawAesGcmStoredKey) encryptMe(ctx *storedKeysCtx) error {
	if k.EncryptedKey != nil {
		// Seems like it is already encrypted
		// Checking that we can decrypt it just in case
		log_dbg("Verifying encryption for key \"%s\"", k.Name)
		decryptedKey, reencryptNeeded, err := decryptKeyData(k, k.EncryptedKey, k.EncryptedByKind, k.EncryptionKeyName, ctx)
		if err != nil {
			return err
		}
		k.DecryptedKey = decryptedKey
		if !reencryptNeeded {
			return nil
		}
	}
	encryptedKey, encryptedByKind, err := encryptKeyData(k, k.DecryptedKey, k.EncryptionKeyName, ctx)
	if err != nil {
		return err
	}
	k.EncryptedKey = encryptedKey
	k.EncryptedByKind = encryptedByKind
	return nil
}

func (k *rawAesGcmStoredKey) decryptMe(ctx *storedKeysCtx) error {
	decryptedKey, _, err := decryptKeyData(k, k.EncryptedKey, k.EncryptedByKind, k.EncryptionKeyName, ctx)
	if err != nil {
		return err
	}
	k.DecryptedKey = decryptedKey
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
	k.CreationTime = decoded.CreationTime
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
		EncryptionKeyName: k.EncryptionKeyName,
		CreationTime:      k.CreationTime})

	if err != nil {
		return "", nil, errors.New(fmt.Sprintf("Failed to marshal key %s: %s", k.Name, err.Error()))
	}
	return rawAESGCMKey, data, nil
}

// Implementation of storedKeyIface for aws keys

func newAwsKey(name, kind, creationTime string, data []byte) (*awsStoredKey, error) {
	var awsk awsStoredKey
	err := json.Unmarshal(data, &awsk)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("invalid json: %v", data))
	}
	awsk.Name = name
	awsk.Kind = kind
	awsk.CreationTime = creationTime
	return &awsk, nil
}

func (k *awsStoredKey) name() string {
	return k.Name
}

func (k *awsStoredKey) kind() string {
	return k.Kind
}

func (k *awsStoredKey) needRewrite(settings *storedKeyConfig, ctx *storedKeysCtx) (bool, error) {
	// since we don't need to encrypt anything in this case, it seems like
	// it would be simpler to always rewrite it on disk
	return true, nil
}

func (k *awsStoredKey) encryptMe(ctx *storedKeysCtx) error {
	// Nothing to encrypt here, configuration should contain no secrets
	return nil
}

func (k *awsStoredKey) decryptMe(ctx *storedKeysCtx) error {
	return nil
}

func (k *awsStoredKey) encryptData(data []byte) ([]byte, error) {
	if k.KeyArn == "TEST_AWS_KEY_ARN" {
		// This code should be used for test purposes only
		log_dbg("Encrypting data using test key")
		zero_key := make([]byte, 32)
		return aesgcmEncrypt(zero_key, data), nil
	}
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
	if k.KeyArn == "TEST_AWS_KEY_ARN" {
		// This code should be used for test purposes only
		log_dbg("Decrypting data using test key")
		zero_key := make([]byte, 32)
		return aesgcmDecrypt(zero_key, data)
	}
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

// Implementation of storedKeyIface for kmip keys

func newKmipKey(name, kind, creationTime, encryptionKeyName string, isEncrypted bool, data []byte, keySettings *storedKeyConfig) (*kmipStoredKey, error) {
	type kmipKeyTmp struct {
		KmipId             string `json:"kmipId"`
		Host               string `json:"host"`
		Port               int    `json:"port"`
		KeyCertPath        string `json:"keyCertPath"`
		Passphrase         []byte `json:"keyPassphrase"`
		EncryptionApproach string `json:"encryptionApproach"`
	}
	var decoded kmipKeyTmp
	err := json.Unmarshal(data, &decoded)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("invalid raw key json: %s", err.Error()))
	}
	rawKeyInfo := &kmipStoredKey{
		Name:               name,
		Kind:               kind,
		KmipId:             decoded.KmipId,
		Host:               decoded.Host,
		Port:               decoded.Port,
		KeyCertPath:        decoded.KeyCertPath,
		EncryptionApproach: decoded.EncryptionApproach,
		EncryptionKeyName:  encryptionKeyName,
		CreationTime:       creationTime,
	}
	if isEncrypted {
		rawKeyInfo.EncryptedPassphrase = data
		rawKeyInfo.EncryptedByKind = keySettings.EncryptByKind
	} else {
		rawKeyInfo.decryptedPassphrase = data
	}
	return rawKeyInfo, nil
}

func (k *kmipStoredKey) name() string {
	return k.Name
}

func (k *kmipStoredKey) kind() string {
	return k.Kind
}

func (k *kmipStoredKey) needRewrite(settings *storedKeyConfig, ctx *storedKeysCtx) (bool, error) {
	keyIface, err := readKeyRaw(settings, k.Name)
	if err != nil {
		log_dbg("key %s read error: %s", k.Name, err.Error())
		return true, nil
	}
	onDiskKey, ok := keyIface.(*kmipStoredKey)
	if !ok {
		log_dbg("key %s changed type, rewriting", k.Name)
		return true, nil
	}

	if k.EncryptedPassphrase != nil && bytes.Equal(k.EncryptedPassphrase, onDiskKey.EncryptedPassphrase) {
		// Both keys are encrypted and encrypted data matches,
		// there is no need to decrypt anything.
		// Copy encrypted pass because we don't want to compare them
		onDiskKey.decryptedPassphrase = k.decryptedPassphrase
		return !reflect.DeepEqual(k, onDiskKey), nil
	}

	if k.decryptedPassphrase == nil {
		err = decryptKey(k, ctx)
		if err != nil {
			return false, err
		}
	}
	if onDiskKey.decryptedPassphrase == nil {
		err = decryptKey(onDiskKey, ctx)
		if err != nil {
			return false, err
		}
	}

	// copy encrypted pass because we don't want to compare them
	onDiskKey.EncryptedPassphrase = k.EncryptedPassphrase
	return !reflect.DeepEqual(k, onDiskKey), nil
}

func (k *kmipStoredKey) encryptMe(ctx *storedKeysCtx) error {
	if k.EncryptedPassphrase != nil {
		// Seems like it is already encrypted
		// Checking that we can decrypt it just in case
		log_dbg("Verifying encryption for key \"%s\"", k.Name)
		decryptedPass, reencryptNeeded, err := decryptKeyData(k, k.EncryptedPassphrase, k.EncryptedByKind, k.EncryptionKeyName, ctx)
		if err != nil {
			return err
		}
		k.decryptedPassphrase = decryptedPass
		if !reencryptNeeded {
			return nil
		}
	}
	encryptedPass, encryptedByKind, err := encryptKeyData(k, k.decryptedPassphrase, k.EncryptionKeyName, ctx)
	if err != nil {
		return err
	}
	k.EncryptedPassphrase = encryptedPass
	k.EncryptedByKind = encryptedByKind
	return nil
}

func (k *kmipStoredKey) decryptMe(ctx *storedKeysCtx) error {
	decryptedPass, _, err := decryptKeyData(k, k.EncryptedPassphrase, k.EncryptedByKind, k.EncryptionKeyName, ctx)
	if err != nil {
		return err
	}
	k.decryptedPassphrase = decryptedPass
	return nil
}

func (k *kmipStoredKey) encryptData(data []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (k *kmipStoredKey) decryptData(data []byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (k *kmipStoredKey) unmarshal(data json.RawMessage) error {
	err := json.Unmarshal(data, k)
	if err != nil {
		return errors.New(fmt.Sprintf("invalid raw key json: %s", err.Error()))
	}
	return nil
}

func (k *kmipStoredKey) usesSecretManagementKey() bool {
	return k.EncryptionKeyName == "encryptionService"
}

func (k *kmipStoredKey) marshal() (storedKeyType, []byte, error) {
	if k.EncryptedPassphrase == nil {
		return "", nil, errors.New(fmt.Sprintf("Cant' store key \"%s\" to disk because the key is not encrypted", k.Name))
	}
	data, err := json.Marshal(k)

	if err != nil {
		return "", nil, errors.New(fmt.Sprintf("Failed to marshal key %s: %s", k.Name, err.Error()))
	}
	return kmipKey, data, nil
}
