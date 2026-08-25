// @author Couchbase <info@couchbase.com>
// @copyright 2024-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.

package azureutils

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/couchbase/tools-common/types/v2/ptr"
)

type OperationArgs struct {
	KeyURL           string
	Algorithm        string
	CredentialsChain string
	TimeoutDuration  time.Duration
}

// EncryptedData is everything that must be persisted alongside the cipher text
// in order to be able to decrypt it later. KeyVersion is always set. IV and
// AuthTag are only set for the algorithms that use them, see
// AlgorithmUsesIVAndAuthTag
type EncryptedData struct {
	CipherText []byte
	KeyVersion string
	IV         []byte
	AuthTag    []byte
}

var supportedAlgorithms = map[string]struct {
	azureAlgorithm azkeys.EncryptionAlgorithm
	// Whether Key Vault generates an initialization vector and an
	// authentication tag on encrypt. Both have to be stored next to the
	// cipher text and sent back on decrypt. Supplying our own IV is not
	// allowed for these, and sending an IV for an algorithm that does not
	// take one makes the operation fail
	usesIVAndAuthTag bool
	// Whether the algorithm can bind additional authenticated data. Passing
	// AD for an algorithm that cannot bind it is treated as a caller error
	// rather than quietly ignoring the argument internally
	supportsAD bool
}{
	"A128GCM":    {azkeys.EncryptionAlgorithmA128GCM, true, true},
	"A192GCM":    {azkeys.EncryptionAlgorithmA192GCM, true, true},
	"A256GCM":    {azkeys.EncryptionAlgorithmA256GCM, true, true},
	"RSAOAEP256": {azkeys.EncryptionAlgorithmRSAOAEP256, false, false},
}

// AlgorithmUsesIVAndAuthTag reports whether Key Vault returns an
// initialization vector and an authentication tag for the algorithm on
// encrypt, and expects both of them back on decrypt
func AlgorithmUsesIVAndAuthTag(algorithm string) bool {
	return supportedAlgorithms[algorithm].usesIVAndAuthTag
}

// AlgorithmSupportsAD reports whether the algorithm can bind additional
// authenticated data
func AlgorithmSupportsAD(algorithm string) bool {
	return supportedAlgorithms[algorithm].supportsAD
}

func KmsEncrypt(opArgs OperationArgs, plainText, AD []byte) (*EncryptedData, error) {
	if len(plainText) == 0 {
		return nil, fmt.Errorf("no data to encrypt")
	}

	if err := validateArgs(opArgs, AD); err != nil {
		return nil, err
	}

	toEncrypt := []byte(base64.URLEncoding.EncodeToString(plainText))
	options, err := getEncrOptions(toEncrypt, AD, opArgs.Algorithm)
	if err != nil {
		return nil, err
	}

	baseURL, keyName, err := parseAzureURL(opArgs.KeyURL)
	if err != nil {
		return nil, err
	}

	client, err := getAzureClient(baseURL, opArgs.CredentialsChain)
	if err != nil {
		return nil, err
	}

	ctx, cancel := getContextWithTimeout(opArgs.TimeoutDuration)
	defer cancel()

	res, err := client.Encrypt(ctx, keyName, "", *options, nil)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt data: %w", err)
	}

	if res.Result == nil {
		return nil, fmt.Errorf("empty cipher text returned")
	}

	if res.KID == nil {
		return nil, fmt.Errorf("no key ID returned")
	}

	version := res.KID.Version()
	if version == "" {
		return nil, fmt.Errorf("no key version returned")
	}

	encrData := &EncryptedData{CipherText: res.Result, KeyVersion: version}

	if AlgorithmUsesIVAndAuthTag(opArgs.Algorithm) {
		if len(res.IV) == 0 {
			return nil, fmt.Errorf("no initialization vector returned for algorithm %s", opArgs.Algorithm)
		}
		if len(res.AuthenticationTag) == 0 {
			return nil, fmt.Errorf("no authentication tag returned for algorithm %s", opArgs.Algorithm)
		}
		encrData.IV = res.IV
		encrData.AuthTag = res.AuthenticationTag
	}

	return encrData, nil
}

func KmsDecrypt(opArgs OperationArgs, encrData EncryptedData, AD []byte) ([]byte, error) {
	if len(encrData.CipherText) == 0 {
		return nil, fmt.Errorf("no data to decrypt")
	}

	if err := validateArgs(opArgs, AD); err != nil {
		return nil, err
	}

	needsIVAndAuthTag := AlgorithmUsesIVAndAuthTag(opArgs.Algorithm)
	if needsIVAndAuthTag {
		if len(encrData.IV) == 0 {
			return nil, fmt.Errorf("missing initialization vector required by algorithm %s", opArgs.Algorithm)
		}
		if len(encrData.AuthTag) == 0 {
			return nil, fmt.Errorf("missing authentication tag required by algorithm %s", opArgs.Algorithm)
		}
	}

	options, err := getEncrOptions(encrData.CipherText, AD, opArgs.Algorithm)
	if err != nil {
		return nil, err
	}

	if needsIVAndAuthTag {
		options.IV = encrData.IV
		options.AuthenticationTag = encrData.AuthTag
	}

	baseURL, keyName, err := parseAzureURL(opArgs.KeyURL)
	if err != nil {
		return nil, err
	}

	client, err := getAzureClient(baseURL, opArgs.CredentialsChain)
	if err != nil {
		return nil, err
	}

	ctx, cancel := getContextWithTimeout(opArgs.TimeoutDuration)
	defer cancel()

	res, err := client.Decrypt(ctx, keyName, encrData.KeyVersion, *options, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data: %w", err)
	}

	if res.Result == nil {
		return nil, fmt.Errorf("empty plain text returned")
	}

	plain, err := base64.URLEncoding.DecodeString(string(res.Result))
	if err != nil {
		return nil, fmt.Errorf("could not base64 decode key: %w", err)
	}

	return plain, nil
}

func validateArgs(opArgs OperationArgs, AD []byte) error {
	if opArgs.KeyURL == "" {
		return fmt.Errorf("no Azure Key Vault URL")
	}

	if opArgs.Algorithm == "" {
		return fmt.Errorf("no encryption algorithm")
	}

	trimmedChain := strings.TrimSpace(opArgs.CredentialsChain)
	if trimmedChain == "" {
		return fmt.Errorf("credentials chain cannot be empty")
	}
	chainParts := strings.Split(trimmedChain, ",")
	for _, part := range chainParts {
		if part == "defaultCredentialsChain" && len(chainParts) != 1 {
			return fmt.Errorf("defaultCredentialsChain must not be mixed with other credential options in chain")
		}
		if strings.TrimSpace(part) == "" {
			return fmt.Errorf("credentials chain contains an empty value")
		}
	}

	// Checked here, and not where the request parameters are built, so that an
	// unknown algorithm is reported as such instead of as an AD mismatch.
	if _, err := getAzureKeysEncryptionAlgorithm(opArgs.Algorithm); err != nil {
		return err
	}

	if len(AD) > 0 && !AlgorithmSupportsAD(opArgs.Algorithm) {
		return fmt.Errorf("additional authenticated data cannot be used with "+
			"algorithm %s, it must not be passed", opArgs.Algorithm)
	}

	return nil
}

func getEncrOptions(value, AD []byte, encryptionAlgorithm string) (*azkeys.KeyOperationParameters, error) {
	azKeysEncrAlgorithm, err := getAzureKeysEncryptionAlgorithm(encryptionAlgorithm)
	if err != nil {
		return nil, err
	}
	return &azkeys.KeyOperationParameters{
		Algorithm:                   ptr.To(azKeysEncrAlgorithm),
		Value:                       value,
		AdditionalAuthenticatedData: AD,
	}, nil
}

func getAzureClient(baseURL string, credentialsChain string) (*azkeys.Client, error) {
	var (
		creds         azcore.TokenCredential
		err           error
		errorMessages []string
	)
	if credentialsChain == "defaultCredentialsChain" {
		creds, err = azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("could not get credentials for Azure: %w", err)
		}
	} else {
		var chainCreds []azcore.TokenCredential
		for _, item := range strings.Split(credentialsChain, ",") {
			switch strings.TrimSpace(item) {
			case "environment":
				c, e := azidentity.NewEnvironmentCredential(nil)
				if e == nil {
					chainCreds = append(chainCreds, c)
				} else {
					errorMessages = append(errorMessages, "EnvironmentCredential: "+e.Error())
				}
			case "workloadIdentity":
				c, e := azidentity.NewWorkloadIdentityCredential(nil)
				if e == nil {
					chainCreds = append(chainCreds, c)
				} else {
					errorMessages = append(errorMessages, "WorkloadIdentityCredential: "+e.Error())
				}
			case "managedIdentity":
				c, e := azidentity.NewManagedIdentityCredential(nil)
				if e == nil {
					chainCreds = append(chainCreds, c)
				} else {
					errorMessages = append(errorMessages, "ManagedIdentityCredential: "+e.Error())
				}
			case "azureCli":
				c, e := azidentity.NewAzureCLICredential(nil)
				if e == nil {
					chainCreds = append(chainCreds, c)
				} else {
					errorMessages = append(errorMessages, "AzureCLICredential: "+e.Error())
				}
			case "azureDeveloperCli":
				c, e := azidentity.NewAzureDeveloperCLICredential(nil)
				if e == nil {
					chainCreds = append(chainCreds, c)
				} else {
					errorMessages = append(errorMessages, "AzureDeveloperCLICredential: "+e.Error())
				}
			default:
				return nil, fmt.Errorf("unsupported credential type in chain: %q", strings.TrimSpace(item))
			}
		}
		if len(chainCreds) == 0 {
			return nil, fmt.Errorf("could not setup credentials chain: %s", strings.Join(errorMessages, ";"))
		}
		creds, err = azidentity.NewChainedTokenCredential(chainCreds, nil)
		if err != nil {
			return nil, fmt.Errorf("could not create chained token credential: %w", err)
		}
	}

	client, err := azkeys.NewClient(baseURL, creds, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create an Azure KMS client: %w", err)
	}

	return client, nil
}

func getAzureKeysEncryptionAlgorithm(algorithm string) (azkeys.EncryptionAlgorithm, error) {
	if len(strings.TrimSpace(algorithm)) == 0 {
		return "", fmt.Errorf("empty encryption algorithm")
	}

	properties, ok := supportedAlgorithms[algorithm]
	if !ok {
		return "", fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}

	return properties.azureAlgorithm, nil
}

func checkForVaultOrHsm(host string) error {
	if strings.HasPrefix(host, ".") {
		return fmt.Errorf("no vault or managedhsm name found in domain: %s", host)
	}

	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return fmt.Errorf("no vault or managedhsm name found in domain: %s", host)
	}

	return nil
}

// The Azure Key Value URL is validated as follows:
//
// Format:
// https://{vault-or-hsm-name}.{host-domain}/keys/{key-name}
//
//  1. It must be https
//  3. It must have a {vault-or-hsm-name}
//  3. It must have a {host-domain}
//  4. It must have a path that starts with /keys/
//  5. It must have a {key-name}
//  5. The {key-name} must be the top key name and NOT refer to a specific version of key
//
// If any of these conditions are not met, an error is returned. The error message
// will indicate the specific condition that was not met.
func parseAzureURL(urlStr string) (string, string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse azure key URL: %w", err)
	}

	if u.Scheme != "https" {
		return "", "", fmt.Errorf("azure key URL must be https")
	}

	if u.Host == "" {
		return "", "", fmt.Errorf("no host found in azure key URL")
	}

	if !strings.HasPrefix(u.Path, "/keys/") {
		return "", "", fmt.Errorf("path must be exactly /keys/<name> with no additional segment")
	}

	keyName := strings.TrimPrefix(u.Path, "/keys/")
	if keyName == "" {
		return "", "", fmt.Errorf("no key name found in azure key URL")
	}

	if strings.Contains(keyName, "/") {
		return "", "", fmt.Errorf("key version not allowed in azure key URL, "+
			"use only root key name in: %s", keyName)
	}

	if err := checkForVaultOrHsm(u.Host); err != nil {
		return "", "", err
	}

	return "https://" + u.Host, keyName, nil
}

func getContextWithTimeout(timeoutDuration time.Duration) (context.Context, context.CancelFunc) {
	if timeoutDuration > 0 {
		return context.WithTimeout(context.Background(), timeoutDuration)
	}
	return context.Background(), func() {}
}
