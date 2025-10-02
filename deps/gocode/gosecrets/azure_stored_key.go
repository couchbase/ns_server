// @author Couchbase <info@couchbase.com>
// @copyright 2025-Present Couchbase, Inc.
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
	"reflect"
	"strconv"
	"time"

	"github.com/couchbase/ns_server/deps/gocode/azureutils"
)

type azureStoredKey struct {
	baseStoredKey
	KeyUrl       string `json:"keyUrl"`
	Algorithm    string `json:"algorithm"`
	ReqTimeoutMs int    `json:"reqTimeoutMs"`
}

// Implementation of storedKeyIface for azure keys

func newAzureKey(name, kind, creationTime string, data []byte) (*azureStoredKey, error) {
	var a azureStoredKey
	err := json.Unmarshal(data, &a)
	if err != nil {
		return nil, fmt.Errorf("invalid json: %v", data)
	}
	a.baseStoredKey = baseStoredKey{Name: name, Kind: kind, CreationTime: creationTime}
	return &a, nil
}

func (k *azureStoredKey) needRewrite(settings *storedKeyConfig, state *StoredKeysState, ctx *storedKeysCtx) (bool, int, error) {
	keyIface, vsn, _, err := readKeyRaw(settings, k.Name)
	if err != nil {
		var keyNotFoundErr ErrKeyNotFound
		if !errors.As(err, &keyNotFoundErr) {
			logDbg("key %s read error: %s", k.Name, err.Error())
		}
		return true, vsn, nil
	}
	onDiskKey, ok := keyIface.(*azureStoredKey)
	if !ok {
		logDbg("key %s changed type, rewriting", k.Name)
		return true, vsn, nil
	}
	return !reflect.DeepEqual(k, onDiskKey), vsn, nil
}

func (k *azureStoredKey) ad() []byte {
	return []byte("")
}

func (k *azureStoredKey) asBytes() ([]byte, error) {
	return []byte(
		string(azurekmKey) +
			k.Name +
			k.Kind +
			k.CreationTime +
			k.KeyUrl +
			k.Algorithm +
			strconv.Itoa(k.ReqTimeoutMs)), nil
}

func (k *azureStoredKey) encryptMe(state *StoredKeysState, ctx *storedKeysCtx) error {
	return nil
}

func (k *azureStoredKey) decryptMe(validateKeysProof bool, state *StoredKeysState, ctx *storedKeysCtx) error {
	return nil
}

func (k *azureStoredKey) checkAzureTestKey() (bool, error) {
	if k.KeyUrl == "TEST_AZURE_KEY_URL" {
		return true, nil
	}
	return false, nil
}

func getAzureOperationArgs(k *azureStoredKey) azureutils.OperationArgs {
	maxTimeoutDuration := 5 * time.Minute
	var timeoutDuration time.Duration
	if int64(k.ReqTimeoutMs) > maxTimeoutDuration.Milliseconds() {
		timeoutDuration = maxTimeoutDuration
	} else {
		timeoutDuration = time.Duration(k.ReqTimeoutMs) * time.Millisecond
	}

	return azureutils.OperationArgs{
		KeyURL:          k.KeyUrl,
		Algorithm:       k.Algorithm,
		TimeoutDuration: timeoutDuration,
	}
}

func (k *azureStoredKey) encryptData(data, AD []byte) ([]byte, error) {
	if isTestKey, err := k.checkAzureTestKey(); isTestKey {
		if err != nil {
			return nil, err
		}
		// This code should be used for test purposes only
		logDbg("Encrypting data using test key")
		zero_key := make([]byte, 32)
		return aesgcmEncrypt(zero_key, data, AD), nil
	}

	opArgs := getAzureOperationArgs(k)
	return azureutils.KmsEncrypt(opArgs, data, AD)
}

func (k *azureStoredKey) decryptData(data, AD []byte) ([]byte, error) {
	if isTestKey, err := k.checkAzureTestKey(); isTestKey {
		if err != nil {
			return nil, err
		}
		// This code should be used for test purposes only
		logDbg("Decrypting data using test key")
		zero_key := make([]byte, 32)
		return aesgcmDecrypt(zero_key, data, AD)
	}

	opArgs := getAzureOperationArgs(k)

	return azureutils.KmsDecrypt(opArgs, data, AD)
}

func (k *azureStoredKey) unmarshal(data json.RawMessage) error {
	err := json.Unmarshal(data, k)
	if err != nil {
		return fmt.Errorf("invalid raw key json: %s", err.Error())
	}
	return nil
}

func (k *azureStoredKey) marshal() (storedKeyType, []byte, error) {
	data, err := json.Marshal(k)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal key %s: %s", k.Name, err.Error())
	}
	return azurekmKey, data, nil
}

func (k *azureStoredKey) usesSecretManagementKey() bool {
	return false
}

func (k *azureStoredKey) canBeCached() bool {
	return false
}
