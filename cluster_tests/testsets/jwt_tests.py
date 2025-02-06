# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import os
import testlib
import json


class JWTTests(testlib.BaseTestSet):
    def __init__(self, cluster):
        super().__init__(cluster)
        # Use single endpoint for all JWT operations
        self.endpoint = "/settings/jwt"

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise",
                                           dev_preview=True)

    def setup(self):
        # Disabled by default
        testlib.get_fail(self.cluster, self.endpoint, expected_code=404)

    def teardown(self):
        testlib.delete_succ(self.cluster, self.endpoint)
        testlib.get_fail(self.cluster, self.endpoint, expected_code=404)

    def basic_api_test(self):
        # Load a JWKS that contains valid ES256 and RSA keys.
        jwks_path = os.path.join(testlib.get_resources_dir(), "jwt",
                                 "jwks.json")
        with open(jwks_path, "r") as f:
            jwks = json.load(f)

        # Test adding first issuer
        payload = {
            "enabled": True,
            "jwksUriRefreshIntervalS": 14400,
            "issuers": [
                {
                    "name": "iss1",
                    "audienceHandling": "any",
                    "subClaim": "sub",
                    "audClaim": "aud",
                    "audiences": ["abc"],
                    "signingAlgorithm": "RS256",
                    "publicKeySource": "jwks",
                    "jwks": jwks,
                }
            ],
        }

        testlib.put_succ(self.cluster, self.endpoint, json=payload)

        # Verify first issuer was added
        r = testlib.get_succ(self.cluster, self.endpoint)
        assert len(r.json()["issuers"]) == 1
        assert r.json()["issuers"][0]["name"] == "iss1"

        # Test adding second issuer
        payload["issuers"].append(
            {
                "name": "iss2",
                "audienceHandling": "all",
                "subClaim": "identity",
                "audClaim": "audience",
                "audiences": ["test_audience"],
                "signingAlgorithm": "ES256",
                "publicKeySource": "jwks",
                "jwks": jwks,
            }
        )

        testlib.put_succ(self.cluster, self.endpoint, json=payload)

        # Verify both issuers exist
        r = testlib.get_succ(self.cluster, self.endpoint)
        assert len(r.json()["issuers"]) == 2
        issuer_names = [i["name"] for i in r.json()["issuers"]]
        assert "iss1" in issuer_names
        assert "iss2" in issuer_names

        # Test removing first issuer
        payload["issuers"] = [
            iss for iss in payload["issuers"] if iss["name"] != "iss1"
        ]
        testlib.put_succ(self.cluster, self.endpoint, json=payload)

        # Verify only second issuer remains
        r = testlib.get_succ(self.cluster, self.endpoint)
        assert len(r.json()["issuers"]) == 1
        assert r.json()["issuers"][0]["name"] == "iss2"

        # Test invalid algorithm
        payload["issuers"].append(
            {
                "name": "iss3",
                "audienceHandling": "all",
                "subClaim": "identity",
                "audClaim": "audience",
                "audiences": ["test_audience"],
                "signingAlgorithm": "EdDSA",
                "publicKeySource": "jwks",
                "jwks": jwks,
            }
        )

        r = testlib.put_fail(
            self.cluster, self.endpoint, expected_code=400, json=payload
        )
        assert (
            r.json()["errors"]["issuers"][1]["jwks"]
            == f"No suitable keys in JWKS for signing algorithm: 'EdDSA'"
        )

    def pem_api_test(self):
        available_algorithms = [
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
            "ES256",
            "ES384",
            "ES512",
            "EdDSA",
        ]
        pem_files = [f
            for f in os.listdir(os.path.join(testlib.get_resources_dir(),
                                              "jwt"))
            if f.endswith(".pem") and "invalid" not in f
        ]
        # We should have test files for RSA, ES256, ES384, ES512, and EdDSA
        expected_pem_count = 7
        assert len(pem_files) == expected_pem_count, (
            f"Expected {expected_pem_count} PEM files but found "
            f"{len(pem_files)}: {pem_files}"
        )

        for pem_file in pem_files:
            good_algos = []
            pem_path = os.path.join(testlib.get_resources_dir(), "jwt",
                                    pem_file)
            with open(pem_path, "r") as f:
                public_key = f.read()
                algorithm = pem_file.split("_")[1]

            if algorithm.startswith("rsa"):
                # The RSA public key is valid for all RSA algorithms - these
                # differ only in their hash computation or padding.
                good_algos.extend(
                    ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]
                )
            elif algorithm.startswith("es"):
                # The curve must match the specified algorithm. ES256 is
                # compatible with P-256, ES384 with P-384, ES512 with P-521 and
                # ES256K with secp256k1.
                good_algos.extend([algorithm.upper()])
            elif algorithm.startswith("ed"):
                # EdDSA is compatible with Ed25519 and Ed448.
                good_algos.extend(["EdDSA"])

            for algorithm in good_algos:
                issuer_config = {
                    "name": f"issuer_{algorithm}",
                    "audienceHandling": "all",
                    "subClaim": "sub",
                    "audClaim": "aud",
                    "audiences": ["test_" + algorithm],
                    "signingAlgorithm": algorithm,
                    "publicKeySource": "pem",
                    "publicKey": public_key,
                }

                payload = {
                    "enabled": True,
                    "jwksUriRefreshIntervalS": 14400,
                    "issuers": [issuer_config],
                }

                testlib.put_succ(self.cluster, self.endpoint, json=payload)

                r = testlib.get_succ(self.cluster, self.endpoint)
                assert len(r.json()["issuers"]) == 1
                returned_issuer = r.json()["issuers"][0]
                for key in issuer_config:
                    assert returned_issuer[key] == issuer_config[key], (
                        f"Mismatch in {key}: expected {issuer_config[key]}, "
                        f"got {returned_issuer[key]}"
                    )

            # Exercise the error handling code by attempting to use the key with
            # algorithms it is not compatible with.
            for bad_algo in set(available_algorithms) - set(good_algos):
                issuer_config = {
                    "name": f"issuer_{algorithm}",
                    "audienceHandling": "all",
                    "subClaim": "sub",
                    "audClaim": "aud",
                    "audiences": ["test_" + algorithm],
                    "signingAlgorithm": bad_algo,
                    "publicKeySource": "pem",
                    "publicKey": public_key,
                }

                payload = {
                    "enabled": True,
                    "jwksUriRefreshIntervalS": 14400,
                    "issuers": [issuer_config],
                }

                r = testlib.put_fail(
                    self.cluster, self.endpoint, expected_code=400, json=payload
                )
                # Only get mismatch error when both the key algorithm and
                # requested algorithm are ES*
                if algorithm.startswith("ES") and bad_algo.startswith("ES"):
                    assert (
                        r.json()["errors"]["issuers"][0]["publicKey"]
                        == f"Mismatch between algorithm in key:'{algorithm}' "
                        f"and signing algorithm:'{bad_algo}'"
                    )
                else:
                    # For all other cases, we get an invalid key error
                    assert (
                        r.json()["errors"]["issuers"][0]["publicKey"]
                        == f"Invalid key for '{bad_algo}' signing algorithm"
                    )

    def invalid_pem_test(self):
        invalid_pem = "mock_rsa_invalid_public.pem"
        pem_path = os.path.join(testlib.get_resources_dir(), "jwt", invalid_pem)
        if not os.path.exists(pem_path):
            raise RuntimeError(
                f"Required test file not found: {invalid_pem}. "
            )

        with open(pem_path, "r") as f:
            public_key = f.read()

            issuer_config = {
                "name": "issuer_short_RS256",
                "audienceHandling": "all",
                "subClaim": "sub",
                "audClaim": "aud",
                "audiences": ["test_short_RS256"],
                "signingAlgorithm": "RS256",
                "publicKeySource": "pem",
                "publicKey": public_key,
            }

            payload = {
                "enabled": True,
                "jwksUriRefreshIntervalS": 14400,
                "issuers": [issuer_config],
            }

            r = testlib.put_fail(
                self.cluster, self.endpoint, expected_code=400, json=payload
            )
            assert (
                r.json()["errors"]["issuers"][0]["publicKey"]
                == "The specified key has 1024 bits. Key length should be "
                "between 2048 and 16384"
            )
