package azureutils

import (
	"bytes"
	"flag"
	"fmt"
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

var AllowedDomains = []string{"vault.azure.net",
	"vault.azure.cn",
	"vault.usgovcloudapi.net",
	"vault.microsoftazure.de",
	"managedhsm.azure.net",
	"managedhsm.azure.cn",
	"managedhsm.usgovcloudapi.net",
	"managedhsm.microsoftazure.de"}

func TestGcpEncryptDecrypt(t *testing.T) {
	if *keyURL == "" {
		t.Fatalf("Key URL is not set, use: go test -key-url=<keyURL>")
	}

	plainTextEncrypt := []byte("These are my secrets")
	AD := []byte("These are my additional authenticated data")

	opArgs := OperationArgs{
		KeyURL:          *keyURL,
		Algorithm:       "RSAOAEP256",
		AllowedDomains:  AllowedDomains,
		TimeoutDuration: 5 * time.Minute,
	}

	encryptedText, err := KmsEncrypt(opArgs, plainTextEncrypt, AD)
	if err != nil {
		t.Fatalf("Could not encrypt data: %s", err.Error())
	}

	plainTextDecrypt, err := KmsDecrypt(opArgs, encryptedText, AD)
	if err != nil {
		t.Fatalf("Could not decrypt data: %s", err.Error())
	}

	if !bytes.Equal(plainTextEncrypt, plainTextDecrypt) {
		t.Fatalf("Mismatch: %s != %s", string(plainTextEncrypt), string(plainTextDecrypt))
	}
}

func TestParseAzureURL(t *testing.T) {
	for _, domain := range AllowedDomains {
		url := fmt.Sprintf("https://nav-test-keyvalue.%s/keys/NavTestKey", domain)
		baseURL, keyName, err := parseAzureURL(url, AllowedDomains)
		t.Logf("Base URL: %s, Key Name: %s", baseURL, keyName)
		if err != nil {
			t.Fatalf("Could not parse Azure URL for domain %s: %s", domain, err.Error())
			continue
		}

		wantBase := fmt.Sprintf("https://nav-test-keyvalue.%s", domain)
		if baseURL != wantBase {
			t.Fatalf("Base URL mismatch for domain %s: got %s, expected %s", domain, baseURL, wantBase)
		}

		if keyName != "NavTestKey" {
			t.Fatalf("Key Name mismatch for domain %s: got %s, expected %s", domain, keyName, "NavTestKey")
		}
	}

	_, _, err := parseAzureURL("http://nav-test-keyvalue.vault.azure.net/keys/NavTestKey", AllowedDomains)
	requireErrEqual(t, err, "azure key URL must be https")

	_, _, err = parseAzureURL("https://.vault.azure.net/keys/NavTestKey", AllowedDomains)
	requireErrEqual(t, err, "no vault or managedhsm name found in domain: .vault.azure.net")

	_, _, err = parseAzureURL("https://blabla/keys/navTestKey", AllowedDomains)
	requireErrEqual(t, err, "no vault or managedhsm name found in domain: blabla")

	_, _, err = parseAzureURL("https:///keys/navTestKey", AllowedDomains)
	requireErrEqual(t, err, "no host found in azure key URL")

	_, _, err = parseAzureURL("https://nav-test-keyvalue.vault.azure.net/NavTestKey/123", AllowedDomains)
	requireErrEqual(t, err, "path must be exactly /keys/<name> with no additional segment")

	_, _, err = parseAzureURL("https://nav-test-keyvalue.vault.azure.net/keys/", AllowedDomains)
	requireErrEqual(t, err, "no key name found in azure key URL")

	_, _, err = parseAzureURL("https://nav-test-keyvalue.vault.azure.net/keys/NavTestKey/123", AllowedDomains)
	requireErrEqual(t, err, "key version not allowed in azure key URL, use only root key name in: NavTestKey/123")

	_, _, err = parseAzureURL("https://nav-test-keyvalue.invaliddomain.azure.net/keys/NavTestKey", AllowedDomains)
	requireErrEqual(t, err, "domain not allowed: invaliddomain.azure.net")

	_, _, err = parseAzureURL("https://vault.azure.net", AllowedDomains)
	requireErrEqual(t, err, "path must be exactly /keys/<name> with no additional segment")
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
