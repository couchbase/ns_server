package hashicorputils

import (
	"bytes"
	"flag"
	"testing"
	"time"
)

// This is a stand alone sanity test that can be used to test the hashicorputils
// against a live HashiCorp Vault Service.
// It can be used for development and debugging of the hashicorputils package.
// Steps to build and run:
// 1. Build the hashicorputils package:
// 		go build -o hashicorputils .
// 2. Run the test:
// 		go test -vault-url=<vaultURL> -mount-path=<mountPath> -key-name=<keyName>
//              -passphrase=<passphrase>
//              -select-ca-opt=<selectCaOpt> -key-path=<keyPath>
//              -cert-path=<certPath> -cb-ca-path=<cbCaPath>
//              -timeout-duration=<timeoutDuration>
// where <vaultURL> is the base Vault server address, <mountPath> is the path
// the transit secrets engine is mounted at and <keyName> is the name of the
// transit key to use for the test.
// Example: -vault-url=https://localhost:8200 -mount-path=/transit
//          -key-name=navKey
// 3. If the test fails, check the Vault URL and token are correct

var vaultURL = flag.String("vault-url", "", "Base Vault server URL")
var mountPath = flag.String("mount-path", "/transit", "Transit mount path")
var keyName = flag.String("key-name", "", "Transit key name")
var passphrase = flag.String("passphrase", "", "Passphrase")
var selectCaOpt = flag.String("select-ca-opt", "", "Select CA Option")
var keyPath = flag.String("key-path", "", "Key Path")
var certPath = flag.String("cert-path", "", "Cert Path")
var cbCaPath = flag.String("cb-ca-path", "", "CB CA Path")
var timeoutDuration = flag.Int("timeout-duration", 60000, "Timeout Duration")

func getClientConfig(Value int) OperationArgs {
	return OperationArgs{
		VaultURL:            *vaultURL,
		MountPath:           *mountPath,
		KeyName:             *keyName,
		DecryptedPassphrase: []byte(*passphrase),
		TimeoutDuration:     time.Duration(Value) * time.Millisecond,
		SelectCaOpt:         *selectCaOpt,
		KeyPath:             *keyPath,
		CertPath:            *certPath,
		CbCaPath:            *cbCaPath,
	}
}

func TestHashicorpEncryptDecrypt(t *testing.T) {
	clientCfg := getClientConfig(*timeoutDuration)
	data := []byte("This is test data")
	AD := []byte("Test ADD")
	AD2 := []byte("Test ADD2")
	encryptedData, err := KmsEncrypt(clientCfg, data, AD)
	if err != nil {
		t.Fatalf("failed to encrypt data: %s", err.Error())
		return
	}

	decryptedData, err := KmsDecrypt(clientCfg, encryptedData, AD2)
	if err == nil {
		t.Fatalf("expected error because invalid AD, got nil")
	}

	decryptedData, err = KmsDecrypt(clientCfg, encryptedData, AD)
	if err != nil {
		t.Errorf("failed to decrypt data: %s", err.Error())
	}

	if !bytes.Equal(data, decryptedData) {
		t.Fatalf("data mismatch: %s != %s", string(data), string(decryptedData))
	}
}

func TestParseVaultAddress(t *testing.T) {
	tests := []struct {
		name      string
		vaultURL  string
		wantHost  string
		expectErr bool
	}{
		{
			name:     "base vault address",
			vaultURL: "https://172.23.104.199:8200",
			wantHost: "https://172.23.104.199:8200",
		},
		{
			name:     "base vault address without port",
			vaultURL: "https://vault.example.com",
			wantHost: "https://vault.example.com",
		},
		{
			name:     "trailing slash is allowed",
			vaultURL: "https://localhost:8200/",
			wantHost: "https://localhost:8200",
		},
		{
			name:     "http scheme",
			vaultURL: "http://localhost:8200",
			wantHost: "http://localhost:8200",
		},
		{
			name:      "missing host",
			vaultURL:  "/v1/transit/encrypt/master",
			expectErr: true,
		},
		{
			name:      "path is not allowed",
			vaultURL:  "https://localhost:8200/couchbase-master-key",
			expectErr: true,
		},
		{
			name:      "full transit endpoint is not allowed",
			vaultURL:  "https://localhost:8200/v1/transit/encrypt/master",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, err := parseVaultAddress(tt.vaultURL)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil (host=%q)", gotHost)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
			if gotHost != tt.wantHost {
				t.Errorf("host mismatch: got %q, want %q", gotHost, tt.wantHost)
			}
		})
	}
}

func TestTransitPath(t *testing.T) {
	tests := []struct {
		name      string
		mountPath string
		op        string
		keyName   string
		want      string
	}{
		{
			name:      "default mount encrypt",
			mountPath: "/transit",
			op:        transitEncrypt,
			keyName:   "couchbase-master-key",
			want:      "/transit/encrypt/couchbase-master-key",
		},
		{
			name:      "default mount decrypt",
			mountPath: "/transit",
			op:        transitDecrypt,
			keyName:   "couchbase-master-key",
			want:      "/transit/decrypt/couchbase-master-key",
		},
		{
			name:      "custom mount path",
			mountPath: "/my-transit",
			op:        transitEncrypt,
			keyName:   "master",
			want:      "/my-transit/encrypt/master",
		},
		{
			name:      "nested mount path",
			mountPath: "/team1/transit",
			op:        transitDecrypt,
			keyName:   "master",
			want:      "/team1/transit/decrypt/master",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := transitPath(tt.mountPath, tt.op, tt.keyName)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateMountPath(t *testing.T) {
	tests := []struct {
		name      string
		mountPath string
		expectErr bool
	}{
		{
			name:      "default mount path",
			mountPath: "/transit",
		},
		{
			name:      "nested mount path",
			mountPath: "/team1/transit",
		},
		{
			name:      "deeply nested mount path",
			mountPath: "/a/b/c/d",
		},
		{
			name:      "empty",
			mountPath: "",
			expectErr: true,
		},
		{
			name:      "missing leading slash",
			mountPath: "transit",
			expectErr: true,
		},
		{
			name:      "nested without leading slash",
			mountPath: "team1/transit",
			expectErr: true,
		},
		{
			name:      "trailing slash",
			mountPath: "/transit/",
			expectErr: true,
		},
		{
			name:      "empty segment",
			mountPath: "/team1//transit",
			expectErr: true,
		},
		// These name no transit engine, and would silently be sent to the
		// wrong vault endpoint if they were normalized instead of rejected.
		{
			name:      "root",
			mountPath: "/",
			expectErr: true,
		},
		{
			name:      "double slash",
			mountPath: "//",
			expectErr: true,
		},
		{
			name:      "parent segment escapes the mount point",
			mountPath: "/transit/../sys",
			expectErr: true,
		},
		{
			name:      "current dir segment",
			mountPath: "/./transit",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMountPath(tt.mountPath)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
		})
	}
}

func TestValidateKeyName(t *testing.T) {
	tests := []struct {
		name      string
		keyName   string
		expectErr bool
	}{
		// The key name is otherwise opaque, the vault server rejects it if the
		// key doesn't exist.
		{
			name:    "simple key name",
			keyName: "couchbase-master-key",
		},
		{
			name:    "dots within a segment",
			keyName: "key.with.dots",
		},
		{
			name:    "double dot within a segment",
			keyName: "a..b",
		},
		{
			name:      "empty",
			keyName:   "",
			expectErr: true,
		},
		// A key name spanning more than one path segment could send the request
		// outside the configured transit mount point.
		{
			name:      "nested key name",
			keyName:   "keys/master",
			expectErr: true,
		},
		{
			name:      "escapes the mount point",
			keyName:   "../../sys/step-down",
			expectErr: true,
		},
		{
			name:      "leading slash",
			keyName:   "/master",
			expectErr: true,
		},
		{
			name:      "trailing slash",
			keyName:   "master/",
			expectErr: true,
		},
		{
			name:      "current dir",
			keyName:   ".",
			expectErr: true,
		},
		{
			name:      "parent dir",
			keyName:   "..",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeyName(tt.keyName)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err.Error())
			}
		})
	}
}
