// @author Couchbase <info@couchbase.com>
// @copyright 2026-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.
package main

import (
	"bytes"
	"testing"

	"github.com/couchbase/ns_server/deps/gocode/azureutils"
)

func requireEncrDataEqual(t *testing.T, got, want *azureutils.EncryptedData) {
	t.Helper()
	if got.KeyVersion != want.KeyVersion {
		t.Fatalf("key version mismatch: got %q, want %q", got.KeyVersion, want.KeyVersion)
	}
	if !bytes.Equal(got.IV, want.IV) {
		t.Fatalf("IV mismatch: got %v, want %v", got.IV, want.IV)
	}
	if !bytes.Equal(got.AuthTag, want.AuthTag) {
		t.Fatalf("auth tag mismatch: got %v, want %v", got.AuthTag, want.AuthTag)
	}
	if !bytes.Equal(got.CipherText, want.CipherText) {
		t.Fatalf("cipher text mismatch: got %v, want %v", got.CipherText, want.CipherText)
	}
}

func TestAzureEnvelopeRoundTrip(t *testing.T) {
	version := "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name     string
		encrData azureutils.EncryptedData
	}{
		{
			// RSA-OAEP-256
			name: "no IV or tag",
			encrData: azureutils.EncryptedData{
				CipherText: []byte("cipher text"),
				KeyVersion: version,
			},
		},
		{
			// AES-GCM
			name: "IV and tag",
			encrData: azureutils.EncryptedData{
				CipherText: []byte("cipher text"),
				KeyVersion: version,
				IV:         bytes.Repeat([]byte{0xCD}, 12),
				AuthTag:    bytes.Repeat([]byte{0xEF}, 16),
			},
		},
		{
			// No supported algorithm produces this shape, but the three
			// fields are framed independently of each other, so the codec has
			// to round-trip any combination of them being empty.
			name: "IV without tag",
			encrData: azureutils.EncryptedData{
				CipherText: []byte("cipher text"),
				KeyVersion: version,
				IV:         bytes.Repeat([]byte{0xAB}, 12),
			},
		},
		{
			name: "empty cipher text",
			encrData: azureutils.EncryptedData{
				KeyVersion: version,
				IV:         bytes.Repeat([]byte{0xCD}, 12),
				AuthTag:    bytes.Repeat([]byte{0xEF}, 16),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := encodeAzureEnvelope(&tc.encrData)
			if err != nil {
				t.Fatalf("could not encode: %s", err.Error())
			}
			if encoded[0] != AZURE_ENVELOPE_VSN {
				t.Fatalf("expected version byte %d, got %d", AZURE_ENVELOPE_VSN, encoded[0])
			}
			decoded, err := decodeAzureEnvelope(encoded)
			if err != nil {
				t.Fatalf("could not decode: %s", err.Error())
			}
			requireEncrDataEqual(t, decoded, &tc.encrData)
		})
	}
}

func TestAzureEnvelopeRejectsBadData(t *testing.T) {
	valid, err := encodeAzureEnvelope(&azureutils.EncryptedData{
		CipherText: []byte("cipher text"),
		KeyVersion: "0123456789abcdef0123456789abcdef",
		IV:         bytes.Repeat([]byte{0xAB}, 12),
		AuthTag:    bytes.Repeat([]byte{0xEF}, 16),
	})
	if err != nil {
		t.Fatalf("could not encode: %s", err.Error())
	}

	if _, err := decodeAzureEnvelope(nil); err == nil {
		t.Fatalf("expected empty data to be rejected")
	}

	// Every truncation of a valid envelope must be rejected rather than
	// producing a partial result. The cipher text is the trailing field and
	// may legitimately be empty, so stop before it.
	headerLen := len(valid) - len("cipher text")
	for i := 1; i < headerLen; i++ {
		if _, err := decodeAzureEnvelope(valid[:i]); err == nil {
			t.Fatalf("expected truncation to %d bytes to be rejected", i)
		}
	}

	// An oversized length prefix must be rejected instead of being trusted.
	oversized := append([]byte{AZURE_ENVELOPE_VSN}, 0xFF, 0xFF, 0xFF, 0xFF)
	if _, err := decodeAzureEnvelope(oversized); err == nil {
		t.Fatalf("expected oversized field length to be rejected")
	}

	// Anything that does not start with the version byte is corrupt data,
	// not a layout to be guessed at.
	unknownVsn := append([]byte{AZURE_ENVELOPE_VSN + 1}, valid[1:]...)
	if _, err := decodeAzureEnvelope(unknownVsn); err == nil {
		t.Fatalf("expected unknown envelope version to be rejected")
	}
}

func TestAzureEnvelopeRejectsOversizedFields(t *testing.T) {
	_, err := encodeAzureEnvelope(&azureutils.EncryptedData{
		CipherText: []byte("cipher text"),
		KeyVersion: string(bytes.Repeat([]byte{'a'}, AZURE_MAX_ENVELOPE_FIELD_SIZE+1)),
	})
	if err == nil {
		t.Fatalf("expected oversized key version to be rejected")
	}
}

// The AD is only handed to Key Vault for the algorithms that can bind it;
// azureutils rejects the request outright for any other algorithm.
func TestAzureADIsOnlyPassedForAlgorithmsThatCanBindIt(t *testing.T) {
	AD := []byte("additional authenticated data")

	for _, tc := range []struct {
		algorithm string
		wantAD    bool
	}{
		{"A128GCM", true},
		{"A192GCM", true},
		{"A256GCM", true},
		{"RSAOAEP256", false},
	} {
		k := &azureStoredKey{Algorithm: tc.algorithm}
		got := k.azureAD(AD)
		if tc.wantAD {
			if !bytes.Equal(got, AD) {
				t.Fatalf("%s: got AD %q, want %q", tc.algorithm, got, AD)
			}
		} else if got != nil {
			t.Fatalf("%s: got AD %q, want none", tc.algorithm, got)
		}

		// A caller that has no AD to begin with must never gain one.
		if got := k.azureAD(nil); got != nil {
			t.Fatalf("%s: got AD %q from nil, want none", tc.algorithm, got)
		}
	}
}
