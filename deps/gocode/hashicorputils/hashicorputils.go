/**
 * Copyright (C) Couchbase, Inc 2021 - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */

package hashicorputils

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/cert"
)

type OperationArgs struct {
	VaultURL            string
	MountPath           string
	KeyName             string
	TimeoutDuration     time.Duration
	KeyPath             string
	CertPath            string
	CbCaPath            string
	SelectCaOpt         string
	DecryptedPassphrase []byte
}

const (
	transitEncrypt = "encrypt"
	transitDecrypt = "decrypt"
)

func KmsEncrypt(opArgs OperationArgs, data []byte, AD []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to encrypt")
	}

	if err := validateArgs(opArgs); err != nil {
		return nil, err
	}

	ctx, cancel := getContextWithTimeout(opArgs.TimeoutDuration)
	defer cancel()

	client, err := getClient(ctx, opArgs)
	if err != nil {
		return nil, err
	}

	secret, err := client.Logical().WriteWithContext(
		ctx,
		transitPath(opArgs.MountPath, transitEncrypt, opArgs.KeyName),
		map[string]any{
			"plaintext":       data,
			"associated_data": AD,
		},
	)

	if err != nil {
		return nil, err
	}

	if secret == nil {
		return nil, fmt.Errorf("no secret returned")
	}

	if secret.Data["ciphertext"] == nil {
		return nil, fmt.Errorf("no ciphertext returned")
	}

	if encryptedData, ok := secret.Data["ciphertext"].(string); !ok {
		return nil, fmt.Errorf("ciphertext is not a string")
	} else {
		return []byte(encryptedData), nil
	}
}

func KmsDecrypt(opArgs OperationArgs, data []byte, AD []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("no data to decrypt")
	}

	if err := validateArgs(opArgs); err != nil {
		return nil, err
	}

	ctx, cancel := getContextWithTimeout(opArgs.TimeoutDuration)
	defer cancel()

	client, err := getClient(ctx, opArgs)
	if err != nil {
		return nil, err
	}

	out, err := client.Logical().WriteWithContext(
		ctx,
		transitPath(opArgs.MountPath, transitDecrypt, opArgs.KeyName),
		map[string]any{
			"ciphertext":      string(data),
			"associated_data": AD,
		},
	)
	if err != nil {
		return nil, err
	}

	if out.Data["plaintext"] == nil {
		return nil, fmt.Errorf("no plaintext returned")
	}

	if plaintext, ok := out.Data["plaintext"].(string); !ok {
		return nil, fmt.Errorf("plaintext is not a string")
	} else {
		return base64.StdEncoding.DecodeString(plaintext)
	}
}

func getClientSelectCaOpt(selectCaOpt string) (api.SelectCaOpt, error) {
	switch selectCaOpt {
	case "use_sys_ca":
		return api.UseSystemCAs, nil
	case "use_cb_ca":
		return api.UseCaCert, nil
	case "use_sys_and_cb_ca":
		return api.UseSystemCAsAndCaCert, nil
	case "skip_server_cert_verification":
		return api.SkipServerCertVerification, nil
	default:
		return api.UseSystemCAs, fmt.Errorf("invalid ca select option: %s", selectCaOpt)
	}
}

// getClient builds a Vault client from opArgs.
//
// The expected format of the Vault URL is the base Vault server address, i.e.
// [http|https]://<Vault Host>(:<vault port>)? with no path. The Vault request
// path is built separately from the configured transit mount path and key
// name (see transitPath).
func getClient(ctx context.Context, opArgs OperationArgs) (*api.Client, error) {
	host, err := parseVaultAddress(opArgs.VaultURL)
	if err != nil {
		return nil, err
	}

	selectCaOpt, err := getClientSelectCaOpt(opArgs.SelectCaOpt)
	if err != nil {
		return nil, err
	}

	apiTLSConfig := &api.TLSConfigPkcs8{
		CACertPath:         opArgs.CbCaPath,
		ClientCertPath:     opArgs.CertPath,
		ClientKeyPkcs8Path: opArgs.KeyPath,
		CaSelection:        selectCaOpt,
	}

	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("could not create default config: %w", cfg.Error)
	}

	cfg.Address = host
	cfg.Timeout = opArgs.TimeoutDuration
	err = cfg.ConfigureTLSViaPkcs8Key(apiTLSConfig, opArgs.DecryptedPassphrase)
	if err != nil {
		return nil, fmt.Errorf("could not configure TLS: %w", err)
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %w", err)
	}

	certAuth, err := cert.NewCertAuth()
	if err != nil {
		return nil, fmt.Errorf("could not create cert auth: %w", err)
	}

	_, err = client.Auth().Login(ctx, certAuth)
	if err != nil {
		return nil, fmt.Errorf("could not login with cert auth: %w", err)
	}

	return client, nil
}

// parseVaultAddress validates the configured Vault URL and returns the base
// Vault server address, e.g. "https://<host>:8200". The URL must not contain
// a path: the Vault request path is built separately from the configured
// transit mount path and key name (see transitPath). If the host given is
// invalid it will fail.
func parseVaultAddress(vaultURL string) (string, error) {
	parsed, err := url.Parse(vaultURL)
	if err != nil {
		return "", fmt.Errorf("invalid Hashi Corp Vault url: %w", err)
	}

	if parsed.Host == "" {
		return "", fmt.Errorf("a host for the Hashi Corp Vault is required")
	}

	if strings.Trim(parsed.Path, "/") != "" {
		return "", fmt.Errorf("the Hashi Corp Vault url must not contain a " +
			"path; the transit mount path and key name are configured " +
			"separately")
	}

	parsed.Path = ""
	return parsed.String(), nil
}

// transitPath builds the Vault request path for the given transit operation
// ("encrypt" or "decrypt"), e.g. "/transit/encrypt/<key name>". The mount path
// is configurable because the transit secrets engine can be mounted anywhere;
// ns_server defaults it to "/transit", which is where Vault mounts it by
// default.
func transitPath(mountPath, op, keyName string) string {
	return path.Join(mountPath, op, keyName)
}

func validateMountPath(mountPath string) error {
	if mountPath == "" {
		return fmt.Errorf("mount path is required")
	}

	if !strings.HasPrefix(mountPath, "/") {
		return fmt.Errorf("mount path %q must be an absolute path, for "+
			"example \"/transit\"", mountPath)
	}

	segments := strings.Split(strings.TrimPrefix(mountPath, "/"), "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("mount path %q must not contain a trailing "+
				"slash or empty, \".\" or \"..\" path segments", mountPath)
		}
	}

	return nil
}

func validateKeyName(keyName string) error {
	if keyName == "" {
		return fmt.Errorf("key name is required")
	}

	if strings.Contains(keyName, "/") {
		return fmt.Errorf("key name %q must not contain \"/\"", keyName)
	}

	if keyName == "." || keyName == ".." {
		return fmt.Errorf("key name %q must not be \".\" or \"..\"", keyName)
	}

	return nil
}

func validateArgs(opArgs OperationArgs) error {
	if opArgs.VaultURL == "" {
		return fmt.Errorf("vault URL is required")
	}

	// Only the shape of the mount path and key name is checked here. Whether
	// the transit engine and key actually exist is up to the Vault server,
	// which rejects the request if they don't.
	if err := validateMountPath(opArgs.MountPath); err != nil {
		return err
	}

	if err := validateKeyName(opArgs.KeyName); err != nil {
		return err
	}

	if len(opArgs.DecryptedPassphrase) == 0 {
		return fmt.Errorf("passphrase is required")
	}

	if opArgs.SelectCaOpt == "" {
		return fmt.Errorf("select ca option is required")
	}

	if opArgs.KeyPath == "" {
		return fmt.Errorf("key path is required")
	}

	if (opArgs.SelectCaOpt == "use_sys_and_cb_ca" || opArgs.SelectCaOpt == "use_cb_ca") &&
		opArgs.CbCaPath == "" {
		return fmt.Errorf("cbcapath is required")
	}

	return nil
}

func getContextWithTimeout(timeoutDuration time.Duration) (context.Context, context.CancelFunc) {
	if timeoutDuration > 0 {
		return context.WithTimeout(context.Background(), timeoutDuration)
	}
	return context.Background(), func() {}
}
