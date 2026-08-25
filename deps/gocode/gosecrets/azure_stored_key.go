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
	"encoding/binary"
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
	KeyUrl           string `json:"keyUrl"`
	Algorithm        string `json:"algorithm"`
	CredentialsChain string `json:"credentialsChain"`
	ReqTimeoutMs     int    `json:"reqTimeoutMs"`
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

func getAzureOperationArgs(k *azureStoredKey) (*azureutils.OperationArgs, error) {
	if err := validateTimeout(k.ReqTimeoutMs); err != nil {
		return nil, err
	}

	return &azureutils.OperationArgs{
		KeyURL:           k.KeyUrl,
		Algorithm:        k.Algorithm,
		CredentialsChain: k.CredentialsChain,
		TimeoutDuration:  time.Duration(k.ReqTimeoutMs) * time.Millisecond,
	}, nil
}

// Key Vault rejects a request that carries additional authenticated data for
// an algorithm that cannot bind it, so the AD must only be handed over for the
// algorithms that can actually use it. Note that this means the AD is not bound
// to the cipher text unless the key is configured with one of the AES-GCM
// algorithms.
func (k *azureStoredKey) azureAD(AD []byte) []byte {
	if azureutils.AlgorithmSupportsAD(k.Algorithm) {
		return AD
	}
	return nil
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

	opArgs, err := getAzureOperationArgs(k)
	if err != nil {
		return nil, err
	}

	encrData, err := azureutils.KmsEncrypt(*opArgs, data, k.azureAD(AD))
	if err != nil {
		return nil, err
	}

	return encodeAzureEnvelope(encrData)
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

	opArgs, err := getAzureOperationArgs(k)
	if err != nil {
		return nil, err
	}

	encrData, err := decodeAzureEnvelope(data)
	if err != nil {
		return nil, err
	}

	return azureutils.KmsDecrypt(*opArgs, *encrData, k.azureAD(AD))
}

// Azure encrypted data is stored as an envelope that carries everything
// decrypt needs besides the cipher text itself: the Key Vault key version (the
// service encrypts with the current version but wants the exact version back
// on decrypt), and, for the algorithms that use them, the initialization
// vector and the authentication tag.
//
//	byte 0                  AZURE_ENVELOPE_VSN
//	4 bytes + n             key version length, key version
//	4 bytes + n             IV length, IV                    (n may be 0)
//	4 bytes + n             auth tag length, auth tag        (n may be 0)
//	rest                    cipher text
func encodeAzureEnvelope(encrData *azureutils.EncryptedData) ([]byte, error) {
	res := []byte{AZURE_ENVELOPE_VSN}
	for _, field := range [][]byte{
		[]byte(encrData.KeyVersion), encrData.IV, encrData.AuthTag,
	} {
		if len(field) > AZURE_MAX_ENVELOPE_FIELD_SIZE {
			return nil, fmt.Errorf("envelope field too large: len=%d, maxAllowed=%d",
				len(field), AZURE_MAX_ENVELOPE_FIELD_SIZE)
		}
		fieldLen := make([]byte, 4)
		binary.BigEndian.PutUint32(fieldLen, uint32(len(field)))
		res = append(res, fieldLen...)
		res = append(res, field...)
	}
	return append(res, encrData.CipherText...), nil
}

func decodeAzureEnvelope(data []byte) (*azureutils.EncryptedData, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("invalid data length: %d", len(data))
	}

	if data[0] != AZURE_ENVELOPE_VSN {
		return nil, fmt.Errorf("unsupported envelope version: %d", data[0])
	}

	rest := data[1:]
	fields := make([][]byte, 3)
	for i := range fields {
		field, remaining, err := readAzureEnvelopeField(rest)
		if err != nil {
			return nil, err
		}
		fields[i], rest = field, remaining
	}

	return &azureutils.EncryptedData{
		KeyVersion: string(fields[0]),
		IV:         fields[1],
		AuthTag:    fields[2],
		CipherText: rest,
	}, nil
}

func readAzureEnvelopeField(data []byte) ([]byte, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("invalid data length: %d", len(data))
	}
	fieldLen := binary.BigEndian.Uint32(data[0:4])
	if fieldLen > AZURE_MAX_ENVELOPE_FIELD_SIZE {
		return nil, nil, fmt.Errorf("envelope field too large: len=%d, maxAllowed=%d",
			fieldLen, AZURE_MAX_ENVELOPE_FIELD_SIZE)
	}
	data = data[4:]
	if uint32(len(data)) < fieldLen {
		return nil, nil, fmt.Errorf("invalid data length: %d", len(data))
	}
	return data[:fieldLen], data[fieldLen:], nil
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
