// @author Couchbase <info@couchbase.com>
// @copyright 2015-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

func mustNoErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var earlyNotBefore = time.Date(2013, 1, 1, 0, 0, 0, 0, time.UTC)

// that's max date that current golang x509 code supports
var earlyNotAfter = time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC)

func pemIfy(octets []byte, pemType string, out io.Writer) {
	pem.Encode(out, &pem.Block{
		Type:  pemType,
		Bytes: octets,
	})
}

func derToPKey(octets []byte) (pkey *rsa.PrivateKey) {
	pkey, err := x509.ParsePKCS1PrivateKey(octets)
	if err == nil {
		return
	}

	pkeyInt, err2 := x509.ParsePKCS8PrivateKey(octets)
	pkey, rsaPKey := pkeyInt.(*rsa.PrivateKey)
	if err2 == nil && !rsaPKey {
		err2 = errors.New("only rsa keys are supported yet")
	}
	if err2 == nil {
		return
	}

	log.Printf("Failed to parse pkey: %s\nOther error is:", err)
	log.Fatal(err2)
	panic("cannot happen")
}

var keyLength = 2048
// testSSL.sh complains when certificate validity is longer than 824 days
// This apparently comes from Apple's 825 day restriction
// (https://support.apple.com/en-us/103769)
const defaultNotAfterDuration = 824 * 24 * 60 * 60;

func main() {
	var genereateLeaf bool
	var isClient bool
	var commonName string
	var sanIPAddrsArg string
	var sanDNSNamesArg string
	var sanEmailsArg string
	var useSha1 bool
	var pkeyType string
	var notAfterDuration int

	flag.StringVar(&commonName, "common-name", "*", "common name field of certificate (hostname)")
	flag.StringVar(&sanIPAddrsArg, "san-ip-addrs", "", "Subject Alternative Name IP addresses (comma separated)")
	flag.StringVar(&sanDNSNamesArg, "san-dns-names", "", "Subject Alternative Name DNS names (comma separated)")
	flag.StringVar(&sanEmailsArg, "san-emails", "", "Subject Alternative Name Emails (comma separated)")
	flag.BoolVar(&genereateLeaf, "generate-leaf", false, "whether to generate leaf certificate (passing ca cert and pkey via environment variables)")
	flag.StringVar(&pkeyType, "pkey-type", "rsa", "what kind of private key to generate (rsa or ec)")
	flag.BoolVar(&isClient, "client", false, "whether to add client auth extension")

	flag.BoolVar(&useSha1, "use-sha1", false, "whether to use sha1 instead of default sha256 signature algorithm")

	flag.IntVar(&notAfterDuration, "not-after-duration", defaultNotAfterDuration, "time in seconds until NotAfter")

	flag.Parse()

	if genereateLeaf {
		cacertPEM := os.Getenv("CACERT")
		certBlock, rest := pem.Decode(([]byte)(cacertPEM))
		if (string)(rest) != "" || certBlock == nil || certBlock.Type != "CERTIFICATE" {
			log.Fatal("garbage CACERT environment variable")
		}

		capkeyPEM := os.Getenv("CAPKEY")
		pkeyBlock, rest := pem.Decode(([]byte)(capkeyPEM))
		// TODO: support EC keys too, which might be useful sometimes
		if (string)(rest) != "" || pkeyBlock == nil || pkeyBlock.Type != "RSA PRIVATE KEY" {
			log.Fatal("garbage CAPKEY environment variable")
		}

		caCert, err := x509.ParseCertificate(certBlock.Bytes)
		mustNoErr(err)

		pkey := derToPKey(pkeyBlock.Bytes)

		authExt := x509.ExtKeyUsageServerAuth
		if isClient {
			authExt = x509.ExtKeyUsageClientAuth
		}

		leafTemplate := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			NotBefore:    time.Now().UTC().AddDate(0, 0, -1),
			NotAfter:     time.Now().UTC().Add(time.Duration(notAfterDuration) * time.Second),
			Subject: pkix.Name{
				CommonName: commonName,
			},
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			SignatureAlgorithm:    caCert.SignatureAlgorithm,
			ExtKeyUsage:           []x509.ExtKeyUsage{authExt},
			BasicConstraintsValid: true,
		}

                if pkeyType == "ec" {
                    leafTemplate.KeyUsage |= x509.KeyUsageKeyAgreement
                }

		if sanIPAddrsArg != "" {
			ips := []net.IP{}
			ipStrings := strings.Split(sanIPAddrsArg, ",")
			for _, s := range ipStrings {
				ip := net.ParseIP(s)
				if ip == nil {
					log.Fatalf("can't parse address \"%s\"", s)
				}
				ips = append(ips, ip)
			}
			leafTemplate.IPAddresses = ips
		}

		if sanDNSNamesArg != "" {
			leafTemplate.DNSNames = strings.Split(sanDNSNamesArg, ",")
		}

		if sanEmailsArg != "" {
			leafTemplate.EmailAddresses = strings.Split(sanEmailsArg, ",")
		}

		if pkeyType == "rsa" {
			leafPKey, err := rsa.GenerateKey(rand.Reader, keyLength)
			mustNoErr(err)
			certDer, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafPKey.PublicKey, pkey)
			mustNoErr(err)

			pemIfy(certDer, "CERTIFICATE", os.Stdout)
			pemIfy(x509.MarshalPKCS1PrivateKey(leafPKey), "RSA PRIVATE KEY", os.Stdout)
		} else if pkeyType == "ec" {
			leafPKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			certDer, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafPKey.PublicKey, pkey)
			mustNoErr(err)

			pemIfy(certDer, "CERTIFICATE", os.Stdout)
			bytes, err := x509.MarshalECPrivateKey(leafPKey)
			mustNoErr(err)
			pemIfy(bytes, "EC PRIVATE KEY", os.Stdout)
		}
	} else {
		pkey, err := rsa.GenerateKey(rand.Reader, keyLength)
		mustNoErr(err)

		commonName = fmt.Sprintf("Couchbase Server %08x", crc32.ChecksumIEEE(pkey.N.Bytes()))

		template := x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			IsCA:         true,
			NotBefore:    earlyNotBefore,
			NotAfter:     earlyNotAfter,
			Subject: pkix.Name{
				CommonName: commonName,
			},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
		}

		if useSha1 {
			template.SignatureAlgorithm = x509.SHA1WithRSA
		}

		certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &pkey.PublicKey, pkey)
		mustNoErr(err)

		pemIfy(certDer, "CERTIFICATE", os.Stdout)
		pemIfy(x509.MarshalPKCS1PrivateKey(pkey), "RSA PRIVATE KEY", os.Stdout)
	}
}
