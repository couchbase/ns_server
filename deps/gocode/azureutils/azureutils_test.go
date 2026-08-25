package azureutils

import (
	"bytes"
	"flag"
	"testing"
	"time"
)

// This is a stand alone sanity test that can be used to test the azureutils
// against a live Azure Key Vault Service.
// It can be used for development and debugging of the awsutils package.
// Steps to build and run:
// 1. Build the azureutils package:
// 		go build -o azureutils .
// 2. Run the test:
// 		go test -key-url=<keyURL>
// where <keyURL> is the key URL in azure key vault of key to use for the test.
// 		For example:
// 			go test -key-url=https://nav-test-keyvalue.vault.azure.net/keys/NavTestKey
// 3. If the test fails, check the Key URL and Azure credentials are correct.
// By default the test will use the Azure credentials from the enviroment
// it is being run in.

// This must be provided as argument to example: "go test -key-url=<keyURL>"
var keyURL = flag.String("key-url", "", "Key URL")
var algorithm = flag.String("algorithm", "RSAOAEP256", "Algorithm")
var credentialsChain = flag.String("credentials-chain", "defaultCredentialsChain", "Credentials chain")
var timeoutMs = flag.Int("timeout-ms", 60000, "Timeout Duration")
var AllowedDomains = []string{"vault.azure.net",
	"vault.azure.cn",
	"vault.usgovcloudapi.net",
	"vault.microsoftazure.de",
	"managedhsm.azure.net",
	"managedhsm.azure.cn",
	"managedhsm.usgovcloudapi.net",
	"managedhsm.microsoftazure.de"}

func TestAzureEncryptDecrypt(t *testing.T) {
	if *keyURL == "" {
		t.Fatalf("Key URL is not set, use: go test -key-url=<keyURL>")
	}

	plainTextEncrypt := []byte("These are my secrets")

	// Only the algorithms that can bind it are handed the additional
	// authenticated data, the same choice the gosecrets caller makes.
	var AD []byte
	if AlgorithmSupportsAD(*algorithm) {
		AD = []byte("These are my additional authenticated data")
	}

	opArgs := OperationArgs{
		KeyURL:           *keyURL,
		Algorithm:        *algorithm,
		CredentialsChain: *credentialsChain,
		TimeoutDuration:  time.Duration(*timeoutMs) * time.Millisecond,
	}

	encrData, err := KmsEncrypt(opArgs, plainTextEncrypt, AD)
	if err != nil {
		t.Fatalf("Could not encrypt data: %s", err.Error())
	}

	// The IV and the authentication tag have to come back for the algorithms
	// that need them on decrypt, and must be absent for the ones that do not.
	if AlgorithmUsesIVAndAuthTag(*algorithm) {
		if len(encrData.IV) == 0 {
			t.Fatalf("%s must produce an IV", *algorithm)
		}
		if len(encrData.AuthTag) == 0 {
			t.Fatalf("%s must produce an authentication tag", *algorithm)
		}
	} else if len(encrData.IV) != 0 || len(encrData.AuthTag) != 0 {
		t.Fatalf("%s must not produce an IV or an authentication tag", *algorithm)
	}

	plainTextDecrypt, err := KmsDecrypt(opArgs, *encrData, AD)
	if err != nil {
		t.Fatalf("Could not decrypt data: %s", err.Error())
	}

	if !bytes.Equal(plainTextEncrypt, plainTextDecrypt) {
		t.Fatalf("Mismatch: %s != %s", string(plainTextEncrypt), string(plainTextDecrypt))
	}
}

func TestParseAzureURL(t *testing.T) {
	_, _, err := parseAzureURL("http://nav-test-keyvalue.vault.azure.net/keys/NavTestKey")
	requireErrEqual(t, err, "azure key URL must be https")

	_, _, err = parseAzureURL("https://.vault.azure.net/keys/NavTestKey")
	requireErrEqual(t, err, "no vault or managedhsm name found in domain: .vault.azure.net")

	_, _, err = parseAzureURL("https://blabla/keys/navTestKey")
	requireErrEqual(t, err, "no vault or managedhsm name found in domain: blabla")

	_, _, err = parseAzureURL("https:///keys/navTestKey")
	requireErrEqual(t, err, "no host found in azure key URL")

	_, _, err = parseAzureURL("https://nav-test-keyvalue.vault.azure.net/NavTestKey/123")
	requireErrEqual(t, err, "path must be exactly /keys/<name> with no additional segment")

	_, _, err = parseAzureURL("https://nav-test-keyvalue.vault.azure.net/keys/")
	requireErrEqual(t, err, "no key name found in azure key URL")

	_, _, err = parseAzureURL("https://nav-test-keyvalue.vault.azure.net/keys/NavTestKey/123")
	requireErrEqual(t, err, "key version not allowed in azure key URL, use only root key name in: NavTestKey/123")

	_, _, err = parseAzureURL("https://vault.azure.net")
	requireErrEqual(t, err, "path must be exactly /keys/<name> with no additional segment")
}

func TestNegativeCredentialsChain(t *testing.T) {
	// Fixed key URL and algorithm rather than the flags the live test uses:
	// validateArgs checks those before it gets to the chain, so taking them
	// from unset flags would make every assertion below unreachable.
	opArgs := OperationArgs{
		KeyURL:           "https://a-vault.vault.azure.net/keys/a-key",
		Algorithm:        "RSAOAEP256",
		CredentialsChain: "invalid,credentials,chain",
		TimeoutDuration:  time.Duration(*timeoutMs) * time.Millisecond,
	}

	plainTextEncrypt := []byte("These are my secrets")

	// No additional authenticated data here: whether it is accepted depends on
	// the algorithm under test, and this test is only about the chain.
	_, err := KmsEncrypt(opArgs, plainTextEncrypt, nil)
	requireErrEqual(t, err, "unsupported credential type in chain: \"invalid\"")

	opArgs.CredentialsChain = ""
	_, err = KmsEncrypt(opArgs, plainTextEncrypt, nil)
	requireErrEqual(t, err, "credentials chain cannot be empty")

	opArgs.CredentialsChain = "defaultCredentialsChain, environment, workloadIdentity, managedIdentity"
	_, err = KmsEncrypt(opArgs, plainTextEncrypt, nil)
	requireErrEqual(t, err, "defaultCredentialsChain must not be mixed with other credential options in chain")

	opArgs.CredentialsChain = "   ,   "
	_, err = KmsEncrypt(opArgs, plainTextEncrypt, nil)
	requireErrEqual(t, err, "credentials chain contains an empty value")
}

// Whether an algorithm produces an IV and an authentication tag, and whether
// it can bind additional authenticated data, are two separate answers, even
// though the currently supported algorithms agree on both.
func TestAlgorithmProperties(t *testing.T) {
	for _, tc := range []struct {
		algorithm        string
		wantIVAndAuthTag bool
		wantSupportsAD   bool
	}{
		{"A128GCM", true, true},
		{"A192GCM", true, true},
		{"A256GCM", true, true},
		{"RSAOAEP256", false, false},
		{"UNKNOWN", false, false},
		{"", false, false},
	} {
		if got := AlgorithmUsesIVAndAuthTag(tc.algorithm); got != tc.wantIVAndAuthTag {
			t.Fatalf("%s: AlgorithmUsesIVAndAuthTag got %t, want %t",
				tc.algorithm, got, tc.wantIVAndAuthTag)
		}
		if got := AlgorithmSupportsAD(tc.algorithm); got != tc.wantSupportsAD {
			t.Fatalf("%s: AlgorithmSupportsAD got %t, want %t",
				tc.algorithm, got, tc.wantSupportsAD)
		}
	}
}

func TestSupportedAlgorithmsAreAccepted(t *testing.T) {
	for _, algorithm := range []string{
		"A128GCM", "A192GCM", "A256GCM", "RSAOAEP256",
	} {
		if _, err := getAzureKeysEncryptionAlgorithm(algorithm); err != nil {
			t.Fatalf("%s must be supported: %s", algorithm, err.Error())
		}
	}
}

func TestUnsupportedAlgorithmsAreRejected(t *testing.T) {
	for _, algorithm := range []string{
		"INVALID", "CKMAESKEYWRAPPAD", "RSA15",
	} {
		_, err := getAzureKeysEncryptionAlgorithm(algorithm)
		requireErrEqual(t, err, "unsupported encryption algorithm: "+algorithm)
	}
}

func TestDecryptRejectsMissingIVAndTag(t *testing.T) {
	opArgs := OperationArgs{
		KeyURL:           "https://a-vault.vault.azure.net/keys/a-key",
		Algorithm:        "A256GCM",
		CredentialsChain: "defaultCredentialsChain",
		TimeoutDuration:  time.Duration(*timeoutMs) * time.Millisecond,
	}

	encrData := EncryptedData{CipherText: []byte("cipher"), KeyVersion: "v1"}

	_, err := KmsDecrypt(opArgs, encrData, nil)
	requireErrEqual(t, err, "missing initialization vector required by algorithm A256GCM")

	encrData.IV = make([]byte, 12)
	_, err = KmsDecrypt(opArgs, encrData, nil)
	requireErrEqual(t, err, "missing authentication tag required by algorithm A256GCM")
}

func TestADIsRejectedForAlgorithmsThatCannotBindIt(t *testing.T) {
	AD := []byte("These are my additional authenticated data")

	opArgs := OperationArgs{
		KeyURL:           "https://a-vault.vault.azure.net/keys/a-key",
		CredentialsChain: "defaultCredentialsChain",
	}

	for _, tc := range []struct {
		algorithm string
		allowsAD  bool
	}{
		{"A128GCM", true},
		{"A192GCM", true},
		{"A256GCM", true},
		{"RSAOAEP256", false},
	} {
		opArgs.Algorithm = tc.algorithm

		// Leaving the AD out is always valid.
		if err := validateArgs(opArgs, nil); err != nil {
			t.Fatalf("%s: unexpected error without AD: %s", tc.algorithm, err.Error())
		}

		err := validateArgs(opArgs, AD)
		if tc.allowsAD {
			if err != nil {
				t.Fatalf("%s: unexpected error with AD: %s", tc.algorithm, err.Error())
			}
			continue
		}
		requireErrEqual(t, err, "additional authenticated data cannot be used with "+
			"algorithm "+tc.algorithm+", it must not be passed")
	}
}

// The AD mismatch must be reported before either operation reaches Key Vault,
// and an unknown algorithm must still be reported as such rather than as an AD
// mismatch.
func TestADValidationHappensBeforeTheRequest(t *testing.T) {
	AD := []byte("These are my additional authenticated data")

	opArgs := OperationArgs{
		KeyURL:           "https://a-vault.vault.azure.net/keys/a-key",
		Algorithm:        "RSAOAEP256",
		CredentialsChain: "defaultCredentialsChain",
	}

	wantErr := "additional authenticated data cannot be used with " +
		"algorithm RSAOAEP256, it must not be passed"

	_, err := KmsEncrypt(opArgs, []byte("secrets"), AD)
	requireErrEqual(t, err, wantErr)

	encrData := EncryptedData{CipherText: []byte("cipher"), KeyVersion: "v1"}
	_, err = KmsDecrypt(opArgs, encrData, AD)
	requireErrEqual(t, err, wantErr)

	opArgs.Algorithm = "A256CBC"
	_, err = KmsEncrypt(opArgs, []byte("secrets"), AD)
	requireErrEqual(t, err, "unsupported encryption algorithm: A256CBC")
}

func requireErrEqual(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error")
	}
	if err.Error() != want {
		t.Fatalf("error mismatch: got %q, want %q", err.Error(), want)
	}
}
