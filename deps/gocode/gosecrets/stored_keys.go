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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/couchbase/ns_server/deps/gocode/awsutils"
	"os"
	"path/filepath"
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
	CreationTime    string `json:"creationTime"`
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
