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
import jwt
import time
import http.server
import threading
import socketserver


class MockJWKSServer:
    """Mock HTTP server for serving JWKS"""

    def __init__(self, initial_jwks):
        self.jwks = initial_jwks
        self.port = self._get_free_port()
        self.is_available = True

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(handler_self):
                if not self.is_available:
                    handler_self.send_response(503)
                    handler_self.end_headers()
                    return

                handler_self.send_response(200)
                handler_self.send_header("Content-Type", "application/json")
                handler_self.send_header(
                    "Cache-Control", "public, max-age=3600"
                )  # 1 hour cache
                handler_self.end_headers()
                handler_self.wfile.write(json.dumps(self.jwks).encode())

            def log_message(self, format, *args):
                pass

        self.handler = Handler
        self.httpd = socketserver.TCPServer(("", self.port), self.handler)
        self.server_thread = None

    def _get_free_port(self):
        with socketserver.TCPServer(("", 0), None) as s:
            return s.server_address[1]

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self):
        self.server_thread = threading.Thread(target=self.httpd.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()
        self.is_available = True

    def stop(self):
        if self.server_thread:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.server_thread.join()
            self.server_thread = None

    @property
    def url(self):
        return f"http://localhost:{self.port}"

    def set_unavailable(self):
        """Simulate server being down"""
        self.is_available = False

    def set_available(self):
        """Restore server availability"""
        self.is_available = True

    def rotate_keys(self, new_jwks):
        """Update the served JWKS"""
        self.jwks = new_jwks


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
        # Set shorter intervals for testing
        testlib.set_config_key(self.cluster,
                               "{menelaus_web_jwt, jwks_uri_refresh_min_s}", 1)
        testlib.set_config_key(self.cluster,
                                "{jwt_cache, jwks_cooldown_interval_ms}",
                                1000)
        # Disabled by default
        testlib.get_fail(self.cluster, self.endpoint, expected_code=404)

    def teardown(self):
        testlib.delete_config_key(self.cluster,
                                  "{menelaus_web_jwt, jwks_uri_refresh_min_s}")
        testlib.delete_config_key(self.cluster,
                                  "{jwt_cache, jwks_cooldown_interval_ms}")
        testlib.delete_succ(self.cluster, self.endpoint)
        testlib.get_fail(self.cluster, self.endpoint, expected_code=404)

    def create_test_groups(self):
        """Create RBAC groups used by tests"""
        groups = [
            ("jwt_bucket_admins", "bucket_admin[*]"),
            ("jwt_data_admins", "data_reader[*],data_writer[*]"),
        ]
        for name, roles in groups:
            group_data = {"roles": roles, "description":
                          f"JWT test group for {name}"}
            testlib.put_succ(
                self.cluster, f"/settings/rbac/groups/{name}", data=group_data
            )

    def load_jwks(self):
        """Load JWKS from test resources"""
        jwks_path = os.path.join(testlib.get_resources_dir(), "jwt",
                                 "jwks.json")
        with open(jwks_path, "r") as f:
            return json.load(f)

    def configure_jwt(self, maps=None):
        """Configure JWT with optional mapping patterns"""
        issuer = {
            "name": "test-issuer",
            "audienceHandling": "any",
            "subClaim": "sub",
            "audClaim": "aud",
            "audiences": ["test-audience"],
            "signingAlgorithm": "RS256",
            "publicKeySource": "jwks",
            "jwks": self.jwks,
            "jitProvisioning": True,
        }
        if maps:
            issuer.update(maps)

        payload = {
            "enabled": True,
            "jwksUriRefreshIntervalS": 14400,
            "issuers": [issuer],
        }
        testlib.put_succ(self.cluster, self.endpoint, json=payload)

    # REST API Configuration Tests
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
                },
                {
                    "name": "iss2",
                    "audienceHandling": "all",
                    "subClaim": "identity",
                    "audClaim": "audience",
                    "audiences": ["test_audience"],
                    "signingAlgorithm": "ES256",
                    "publicKeySource": "jwks",
                    "jwks": jwks,
                },
                {
                    "name": "iss1",
                    "audienceHandling": "all",
                    "subClaim": "identity",
                    "audClaim": "audience",
                    "audiences": ["test_audience"],
                    "signingAlgorithm": "ES256",
                    "publicKeySource": "jwks",
                    "jwks": jwks,
                },
            ],
        }

        r = testlib.put_fail(
            self.cluster, self.endpoint, expected_code=400, json=payload
        )
        assert (r.json()["errors"]["issuers"] ==
                "Duplicate issuer names not allowed")

        # Test adding issuer with publicKeySource as jwks but without jwks
        payload["issuers"] = [
            {
                "name": "iss2",
                "audienceHandling": "any",
                "subClaim": "sub",
                "audClaim": "aud",
                "audiences": ["abc"],
                "signingAlgorithm": "RS256",
                "publicKeySource": "jwks",
            }
        ]

        r = testlib.put_fail(
            self.cluster, self.endpoint, expected_code=400, json=payload
        )
        assert r.json()["errors"]["issuers"][0]["_"] == "jwks is required"
        payload = {
            "enabled": True,
            "jwksUriRefreshIntervalS": 14400,
            "issuers": [
                {
                    "name": "issuer2",
                    "audienceHandling": "any",
                    "subClaim": "sub",
                    "audClaim": "aud",
                    "audiences": ["abc"],
                    "signingAlgorithm": "RS256",
                    "publicKeySource": "pem",
                }
            ],
        }

        r = testlib.put_fail(
            self.cluster, self.endpoint, expected_code=400, json=payload
        )
        assert r.json()["errors"]["issuers"][0]["_"] == "publicKey is required"

        payload = {
            "enabled": True,
            "jwksUriRefreshIntervalS": 14400,
            "issuers": [
                {
                    "name": "issuer3",
                    "audienceHandling": "any",
                    "subClaim": "sub",
                    "audClaim": "aud",
                    "audiences": ["abc"],
                    "signingAlgorithm": "RS256",
                    "publicKeySource": "jwks_uri",
                }
            ],
        }

        r = testlib.put_fail(
            self.cluster, self.endpoint, expected_code=400, json=payload
        )
        assert r.json()["errors"]["issuers"][0]["_"] == "jwksUri is required"

        payload = {
            "enabled": True,
            "jwksUriRefreshIntervalS": 14400,
            "issuers": [
                {
                    "name": "issuer4",
                    "audienceHandling": "any",
                    "subClaim": "sub",
                    "audClaim": "aud",
                    "audiences": ["abc"],
                    "signingAlgorithm": "RS256",
                }
            ],
        }

        r = testlib.put_fail(
            self.cluster, self.endpoint, expected_code=400, json=payload
        )
        assert (
            r.json()["errors"]["issuers"][0]["_"]
            == "publicKeySource required for algorithm"
        )

        payload = {
            "enabled": True,
            "jwksUriRefreshIntervalS": 14400,
            "issuers": [
                {
                    "name": "issuer5",
                    "audienceHandling": "any",
                    "subClaim": "sub",
                    "audClaim": "aud",
                    "audiences": ["abc"],
                    "signingAlgorithm": "HS256",
                }
            ],
        }

        r = testlib.put_fail(
            self.cluster, self.endpoint, expected_code=400, json=payload
        )
        assert (
            r.json()["errors"]["issuers"][0]["_"]
            == "sharedSecret required for HMAC algorithm"
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
            if f.endswith(".pem") and "invalid" not in f and "private" not in f
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

    def invalid_jwks_test(self):
        jwks_path = os.path.join(testlib.get_resources_dir(), "jwt",
                                "mock_invalid_jwks1.json")
        if not os.path.exists(jwks_path):
            raise RuntimeError(f"Required test file not found: "
                                f"{invalid_jwks}. ")
        with open(jwks_path, "r") as f:
            jwks = json.load(f)

        issuer_config = {
            "name": "ES256_issuer",
            "audienceHandling": "all",
            "subClaim": "sub",
            "audClaim": "aud",
            "audiences": ["test_ES256"],
            "signingAlgorithm": "ES256",
            "publicKeySource": "jwks",
            "jwks": jwks,
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
            r.json()["errors"]["issuers"][0]["jwks"]
            == "Duplicate 'kid' found in JWKS"
            )

        jwks_path = os.path.join(testlib.get_resources_dir(), "jwt",
                                "mock_invalid_jwks2.json")
        if not os.path.exists(jwks_path):
            raise RuntimeError(f"Required test file not found: "
                                f"{invalid_jwks}. ")
        with open(jwks_path, "r") as f:
            jwks = json.load(f)

        issuer_config = {
            "name": "RS256_issuer",
            "audienceHandling": "all",
            "subClaim": "sub",
            "audClaim": "aud",
            "audiences": ["test_RS256"],
            "signingAlgorithm": "RS256",
            "publicKeySource": "jwks",
            "jwks": jwks,
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
            r.json()["errors"]["issuers"][0]["jwks"]
            == "The specified key has 504 bits. Key length should be "
            "between 2048 and 16384; The specified key has 488 bits. Key "
            "length should be between 2048 and 16384"
        )

    # Authentication Tests with Setup
    def auth_setup(self):
        """Setup required for authentication tests"""
        self.create_test_groups()
        self.jwks = self.load_jwks()
        self.base_claims = {
            "iss": "test-issuer",
            "sub": "test-user",
            "aud": "test-audience",
            "exp": int(time.time()) + 3600,
        }

    def direct_auth_test(self):
        """Test JWT authentication without any mapping patterns"""
        self.auth_setup()

        # First test with JIT provisioning disabled
        self.configure_jwt({"jitProvisioning": False})

        claims = self.base_claims.copy()
        claims["groups"] = ["jwt_bucket_admins"]
        token = self.create_token(claims)

        headers = {"Authorization": f"Bearer {token}"}
        r = testlib.get(
            self.cluster, "/pools/default/buckets", auth=None, headers=headers
        )
        assert r.status_code == 401

        # Then test with JIT provisioning enabled
        self.configure_jwt({"jitProvisioning": True})

        r = testlib.get(
            self.cluster, "/pools/default/buckets", auth=None, headers=headers
        )
        assert r.status_code == 200

    def mapped_auth_test(self):
        """Test JWT authentication with mapping patterns"""
        self.auth_setup()
        self.configure_jwt(
            {
                "groupsMaps": [
                    "^prefix-(.*)-suffix$ jwt_\\1_admins",
                    "^data-(.*)$ jwt_\\1_admins",
                ]
            }
        )

        test_cases = [
            ("prefix-bucket-suffix", 200),  # Should map to jwt_bucket_admins
            ("data-data", 200),  # Should map to jwt_data_admins
            ("unknown-group", 401),  # No mapping match
        ]

        for group, expected_code in test_cases:
            claims = self.base_claims.copy()
            claims["groups"] = [group]
            token = self.create_token(claims)

            headers = {"Authorization": f"Bearer {token}"}
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == expected_code

    def validation_test(self):
        """Test JWT validation (exp, nbf, aud, signature)"""
        self.auth_setup()
        self.configure_jwt()
        claims = self.base_claims.copy()
        claims["groups"] = ["jwt_bucket_admins"]

        # Test cases: (claim_modifier, alg, key_id, expected_code)
        test_cases = [
            # expired
            (
                lambda c: {**c, "exp": int(time.time()) - 3600},
                "RS256",
                "2011-04-29",
                401,
            ),
            # future
            (
                lambda c: {**c, "nbf": int(time.time()) + 3600},
                "RS256",
                "2011-04-29",
                401,
            ),
            # wrong audience
            (lambda c: {**c, "aud": "wrong-audience"}, "RS256", "2011-04-29",
             401),
            # wrong signature
            (lambda c: c, "ES256", "es256-key", 401),
        ]

        for modify_claims, alg, key_id, expected_code in test_cases:
            token = self.create_token(modify_claims(claims), key_id=key_id,
                                      alg=alg)
            headers = {"Authorization": f"Bearer {token}"}
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == expected_code

    @staticmethod
    def create_token(claims, key_id="2011-04-29", alg="RS256"):
        """Create a signed JWT token for testing.
        Args:
            claims: Dictionary of JWT claims
            key_id: Key ID to use in JWT header
            alg: Signing algorithm (RS256, ES256, etc)
        Returns:
            Signed JWT token string
        """
        # Handle rotated key
        if key_id == "rotated-key":
            key_file = f"mock_{alg.lower()}_rotated_private_key.pem"
        else:
            key_file = f"mock_{alg.lower()}_private_key.pem"

        with open(os.path.join(testlib.get_resources_dir(), "jwt", key_file),
                  "r") as f:
            private_key = f.read()

        headers = {"kid": key_id}
        return jwt.encode(claims, private_key, algorithm=alg, headers=headers)

    def load_hmac_secrets(self):
        """Load HMAC secrets from test resources"""
        secrets_path = os.path.join(
            testlib.get_resources_dir(), "jwt", "mock_hmac_secrets.json"
        )
        with open(secrets_path, "r") as f:
            return json.load(f)

    def hmac_test(self):
        """Test JWT authentication with HMAC algorithms"""
        self.auth_setup()

        # Load HMAC secrets
        secrets = self.load_hmac_secrets()

        # Test each HMAC algorithm
        for alg, config in secrets.items():
            # Configure JWT with HMAC
            issuer_config = {
                "name": f"hmac-issuer-{alg}",
                "audienceHandling": "any",
                "subClaim": "sub",
                "audClaim": "aud",
                "audiences": ["test-audience"],
                "signingAlgorithm": alg,
                "sharedSecret": config["secret"],
                "jitProvisioning": True,
            }

            payload = {
                "enabled": True,
                "jwksUriRefreshIntervalS": 14400,
                "issuers": [issuer_config],
            }

            testlib.put_succ(self.cluster, self.endpoint, json=payload)

            # Create and test a token
            claims = self.base_claims.copy()
            claims["iss"] = f"hmac-issuer-{alg}"
            claims["groups"] = ["jwt_bucket_admins"]

            token = jwt.encode(claims, config["secret"], algorithm=alg)

            headers = {"Authorization": f"Bearer {token}"}
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == 200

            # Test with wrong secret
            wrong_token = jwt.encode(claims, "wrong-secret", algorithm=alg)
            headers = {"Authorization": f"Bearer {wrong_token}"}
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == 401

    def jwks_uri_test(self):
        """Test JWT authentication with JWKS URI"""
        self.auth_setup()

        # Load test keys
        with open(os.path.join(testlib.get_resources_dir(), "jwt",
                               "jwks.json")) as f:
            initial_jwks = json.load(f)

        with open(
            os.path.join(testlib.get_resources_dir(), "jwt",
                         "jwks_rotated.json")
        ) as f:
            rotated_jwks = json.load(f)

        with MockJWKSServer(initial_jwks) as server:
            # Configure JWT to use JWKS URI
            issuer_config = {
                "name": "jwks-uri-issuer",
                "audienceHandling": "any",
                "subClaim": "sub",
                "audClaim": "aud",
                "audiences": ["test-audience"],
                "signingAlgorithm": "RS256",
                "publicKeySource": "jwks_uri",
                "jwksUri": server.url,
                "jitProvisioning": True,
                "jwksUriHttpTimeoutMs": 5000,
            }

            payload = {
                "enabled": True,
                "jwksUriRefreshIntervalS": 14400,
                "issuers": [issuer_config],
            }

            testlib.put_succ(self.cluster, self.endpoint, json=payload)

            # Test successful key fetch and token validation
            claims = self.base_claims.copy()
            claims["iss"] = "jwks-uri-issuer"
            claims["groups"] = ["jwt_bucket_admins"]
            token = self.create_token(claims)

            headers = {"Authorization": f"Bearer {token}"}
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == 200

            # Test server unavailable, settings change forces invalidation
            server.set_unavailable()
            testlib.put_succ(self.cluster, self.endpoint, json=payload)
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == 401

            # Test key rotation with auto-refresh
            server.set_available()
            # Update settings with short refresh interval for key rotation test
            payload["jwksUriRefreshIntervalS"] = 1
            testlib.put_succ(self.cluster, self.endpoint, json=payload)
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == 200

            server.rotate_keys(rotated_jwks)
            time.sleep(2)  # Wait for auto-refresh to happen

            # Old token is still present in the rotated JWKS
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == 200

            # New token with rotated key
            token = self.create_token(claims, key_id="rotated-key")
            headers = {"Authorization": f"Bearer {token}"}
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == 200

            # Test invalid JWKS response, settings change forces refetch
            server.rotate_keys({"keys": []})  # Empty JWKS
            testlib.put_succ(self.cluster, self.endpoint, json=payload)
            r = testlib.get(
                self.cluster, "/pools/default/buckets", auth=None,
                headers=headers
            )
            assert r.status_code == 401
