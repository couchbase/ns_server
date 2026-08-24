# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""
Browser login tests for OIDC single sign-on.

The tests drive the authorization code flow end to end against a mock
identity provider defined in this file, covering PKCE and PAR, manually
configured and discovered endpoints, plain HTTP and TLS with and without peer
verification, RP-initiated logout, and the negative cases where the provider
denies authorization or the mapped user ends up with no privileges.
"""

import base64
import hashlib
import http.server
import json
import os
import requests
import socketserver
import ssl
import threading
import time
import urllib.parse

import jwt

import testlib
from testlib.util import Service

UI_HEADERS = {"Host": "some_addr", "ns-server-ui": "yes"}

# Sentinel distinguishing "argument not supplied" from an explicit None/[],
# so callers can omit postLogoutRedirectUris rather than defaulting it.
_UNSET = object()


def _b64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _pkce_s256_challenge(verifier: str) -> str:
    h = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url_no_pad(h)


# OIDC Core 1.0 section 3.1.3.6: at_hash is the base64url encoding of the
# left-most half of the hash of the access token, where the hash algorithm is
# the one named by the alg header of the ID token.
_AT_HASH_DIGESTS = {
    "256": hashlib.sha256,
    "384": hashlib.sha384,
    "512": hashlib.sha512,
}


def _at_hash(access_token: str, alg: str) -> str:
    digest = _AT_HASH_DIGESTS[alg[-3:]]
    h = digest(access_token.encode("ascii")).digest()
    return _b64url_no_pad(h[: len(h) // 2])


# =============================================================================
# Mock OIDC Provider
# =============================================================================


class MockOIDCProvider:
    """Mock OIDC provider implementing Authorization Code flow + PKCE + PAR.

    When deny_auth=True the /auth endpoint redirects back with
    error=access_denied instead of issuing a code, allowing tests to verify
    how ns_server handles IdP-side authorization denial.
    """

    def __init__(
        self,
        jwks,
        client_id,
        client_secret,
        token_groups=None,
        use_tls=False,
        tls_certfile=None,
        tls_keyfile=None,
        deny_auth=False,
        id_token_alg="RS256",
    ):
        self.jwks = jwks
        self.client_id = client_id
        self.client_secret = client_secret
        # Assigned by start(), which binds the listening socket.
        self.port = None
        self._httpd = None
        self._thread = None
        self._codes = {}
        self._par_requests = {}
        self._lock = threading.Lock()
        self.token_groups = (
            token_groups if token_groups is not None else ["oidc_admins"]
        )
        self.use_tls = use_tls
        self.tls_certfile = tls_certfile
        self.tls_keyfile = tls_keyfile
        self.deny_auth = deny_auth
        self.id_token_alg = id_token_alg
        self.access_token = "dummy-access-token"

        self._kid = None
        for k in jwks.get("keys", []):
            if k.get("kty") == "RSA":
                self._kid = k.get("kid")
                break

    @property
    def issuer(self):
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://localhost:{self.port}"

    @property
    def discovery_url(self):
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def auth_url(self):
        return f"{self.issuer}/auth"

    @property
    def token_url(self):
        return f"{self.issuer}/token"

    @property
    def jwks_url(self):
        return f"{self.issuer}/jwks"

    @property
    def logout_url(self):
        return f"{self.issuer}/logout"

    def start(self):
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            # Real IdPs keep connections alive, and so must this one: whether
            # a client reuses a pooled connection for a request with different
            # TLS options is part of what these tests cover. Every response
            # therefore has to carry an accurate Content-Length.
            protocol_version = "HTTP/1.1"

            def _send_json(self, code, obj, headers=None):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                if headers:
                    for k, v in headers.items():
                        self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _send_redirect(self, location):
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _parse_client_credentials(self, form):
                authz = self.headers.get("Authorization")
                if authz and authz.startswith("Basic "):
                    raw = base64.b64decode(authz.split(" ", 1)[1]).decode()
                    cid, csec = raw.split(":", 1)
                else:
                    cid = (form.get("client_id") or [None])[0]
                    csec = (form.get("client_secret") or [None])[0]
                return cid, csec

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                path = parsed.path

                if path == "/.well-known/openid-configuration":
                    return self._send_json(
                        200,
                        {
                            "issuer": parent.issuer,
                            "authorization_endpoint": parent.auth_url,
                            "token_endpoint": parent.token_url,
                            "jwks_uri": parent.jwks_url,
                            "end_session_endpoint": parent.logout_url,
                            "pushed_authorization_request_endpoint":
                                f"{parent.issuer}/par",
                            "scopes_supported": ["openid", "profile"],
                            "response_types_supported": ["code"],
                            "grant_types_supported": ["authorization_code"],
                            "subject_types_supported": ["public"],
                            "id_token_signing_alg_values_supported": [
                                parent.id_token_alg
                            ],
                            "token_endpoint_auth_methods_supported": [
                                "client_secret_basic",
                                "client_secret_post",
                            ],
                            "code_challenge_methods_supported": ["S256"],
                        },
                    )

                if path == "/jwks":
                    return self._send_json(
                        200,
                        parent.jwks,
                        headers={"Cache-Control": "public, max-age=60"},
                    )

                if path == "/auth":
                    qs = urllib.parse.parse_qs(parsed.query)
                    client_id = (qs.get("client_id") or [None])[0]
                    if client_id != parent.client_id:
                        return self._send_json(400, {"error": "invalid_client"})

                    request_uri = (qs.get("request_uri") or [None])[0]
                    if request_uri is not None:
                        # PAR flow: resolve auth params from stored request_uri
                        with parent._lock:
                            par = parent._par_requests.pop(request_uri, None)
                        if par is None:
                            return self._send_json(
                                400, {"error": "invalid_request_uri"}
                            )
                        state = par["state"]
                        redirect_uri = par["redirect_uri"]
                        nonce = par["nonce"]
                        code_challenge = par["code_challenge"]
                        code_challenge_method = par["code_challenge_method"]
                    else:
                        state = (qs.get("state") or [None])[0]
                        redirect_uri = (qs.get("redirect_uri") or [None])[0]
                        if state is None or redirect_uri is None:
                            return self._send_json(
                                400, {"error": "invalid_request"}
                            )
                        nonce = (qs.get("nonce") or [None])[0]
                        code_challenge = (
                            qs.get("code_challenge") or [None]
                        )[0]
                        code_challenge_method = (
                            qs.get("code_challenge_method") or [None]
                        )[0]

                    if parent.deny_auth:
                        cb = (
                            redirect_uri
                            + "?"
                            + urllib.parse.urlencode(
                                {"error": "access_denied", "state": state}
                            )
                        )
                        return self._send_redirect(cb)

                    code = _b64url_no_pad(os.urandom(16))
                    with parent._lock:
                        parent._codes[code] = {
                            "redirect_uri": redirect_uri,
                            "nonce": nonce,
                            "code_challenge": code_challenge,
                            "code_challenge_method": code_challenge_method,
                        }

                    cb = (
                        redirect_uri
                        + "?"
                        + urllib.parse.urlencode({"code": code, "state": state})
                    )
                    return self._send_redirect(cb)

                if path == "/logout":
                    qs = urllib.parse.parse_qs(parsed.query)
                    post_logout = (
                        qs.get("post_logout_redirect_uri") or [None]
                    )[0]
                    if post_logout:
                        return self._send_redirect(post_logout)
                    return self._send_json(200, {"status": "ok"})

                return self._send_json(404, {"error": "not_found"})

            def do_POST(self):
                parsed = urllib.parse.urlparse(self.path)
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                form = urllib.parse.parse_qs(body)

                if parsed.path == "/par":
                    cid, csec = self._parse_client_credentials(form)
                    if cid != parent.client_id or csec != parent.client_secret:
                        return self._send_json(401, {"error": "invalid_client"})

                    request_uri = (
                        "urn:ietf:params:oauth:request_uri:"
                        + _b64url_no_pad(os.urandom(16))
                    )
                    with parent._lock:
                        parent._par_requests[request_uri] = {
                            "state": (form.get("state") or [None])[0],
                            "redirect_uri": (
                                form.get("redirect_uri") or [None]
                            )[0],
                            "nonce": (form.get("nonce") or [None])[0],
                            "code_challenge": (
                                form.get("code_challenge") or [None]
                            )[0],
                            "code_challenge_method": (
                                form.get("code_challenge_method") or [None]
                            )[0],
                        }
                    return self._send_json(
                        201, {"request_uri": request_uri, "expires_in": 90}
                    )

                if parsed.path == "/token":
                    grant_type = (form.get("grant_type") or [None])[0]
                    code = (form.get("code") or [None])[0]
                    redirect_uri = (form.get("redirect_uri") or [None])[0]
                    code_verifier = (form.get("code_verifier") or [None])[0]

                    cid, csec = self._parse_client_credentials(form)
                    if cid != parent.client_id or csec != parent.client_secret:
                        return self._send_json(401, {"error": "invalid_client"})

                    if grant_type != "authorization_code" or code is None:
                        return self._send_json(
                            400, {"error": "unsupported_grant_type"}
                        )

                    with parent._lock:
                        code_entry = parent._codes.get(code)

                    if code_entry is None:
                        return self._send_json(400, {"error": "invalid_grant"})
                    if redirect_uri != code_entry["redirect_uri"]:
                        return self._send_json(400, {"error": "invalid_grant"})

                    if code_entry["code_challenge"]:
                        if not code_verifier:
                            return self._send_json(
                                400, {"error": "invalid_request"}
                            )
                        if code_entry["code_challenge_method"] != "S256":
                            return self._send_json(
                                400, {"error": "invalid_request"}
                            )
                        if (
                            _pkce_s256_challenge(code_verifier)
                            != code_entry["code_challenge"]
                        ):
                            return self._send_json(
                                400, {"error": "invalid_grant"}
                            )

                    now = int(time.time())
                    claims = {
                        "iss": parent.issuer,
                        "sub": "testuser",
                        "aud": parent.client_id,
                        "iat": now,
                        "exp": now + 3600,
                        "groups": parent.token_groups,
                        "at_hash": _at_hash(
                            parent.access_token, parent.id_token_alg
                        ),
                    }
                    if code_entry["nonce"]:
                        claims["nonce"] = code_entry["nonce"]

                    priv_key_path = os.path.join(
                        testlib.get_resources_dir(),
                        "jwt",
                        "mock_rsa_private.pem",
                    )
                    with open(priv_key_path, "r") as f:
                        priv = f.read()

                    headers = {"kid": parent._kid} if parent._kid else {}
                    id_token = jwt.encode(
                        claims,
                        priv,
                        algorithm=parent.id_token_alg,
                        headers=headers,
                    )

                    return self._send_json(
                        200,
                        {
                            "access_token": parent.access_token,
                            "token_type": "Bearer",
                            "expires_in": 3600,
                            "id_token": id_token,
                        },
                    )

                return self._send_json(404, {"error": "not_found"})

            def log_message(self, fmt, *args):
                pass

        # Threaded, because a client holding a connection open must not stop
        # the next one from being served. Bound on port 0 with the assigned
        # port read back, rather than choosing a free port up front and
        # binding it later, which leaves a window for something else to take
        # it.
        self._httpd = socketserver.ThreadingTCPServer(("", 0), Handler)
        self.port = self._httpd.server_address[1]
        self._httpd.daemon_threads = True
        if self.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(
                certfile=self.tls_certfile, keyfile=self.tls_keyfile
            )
            self._httpd.socket = ctx.wrap_socket(
                self._httpd.socket, server_side=True
            )
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, daemon=True
        )
        self._thread.start()

    def stop(self):
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


# =============================================================================
# Test Class
# =============================================================================


class OIDCTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            edition="Enterprise",
            num_vbuckets=16,
            include_services=[Service.KV],
            # oidcSettings.clientSecret is an issuer secret, so the encryption
            # prerequisites apply to every issuer these tests configure.
            encryption=True,
        )

    def setup(self):
        r = testlib.get_succ(self.cluster, "/settings/jwt")
        testlib.assert_eq(r.json()["enabled"], False,
                          name="jwt not enabled before configuration")
        testlib.put_succ(
            self.cluster,
            "/settings/rbac/groups/oidc_admins",
            data={"roles": "admin", "description": "OIDC test admins"},
        )
        testlib.set_config_key(
            self.cluster, "{menelaus_web_jwt, jwks_uri_refresh_min_s}", 1
        )
        testlib.set_config_key(
            self.cluster, "{jwt_cache, jwks_cooldown_interval_ms}", 1000
        )

    def teardown(self):
        testlib.delete_config_key(
            self.cluster, "{menelaus_web_jwt, jwks_uri_refresh_min_s}"
        )
        testlib.delete_config_key(
            self.cluster, "{jwt_cache, jwks_cooldown_interval_ms}"
        )
        testlib.ensure_deleted(self.cluster, "/settings/jwt")
        testlib.ensure_deleted(
            self.cluster, "/settings/rbac/groups/oidc_admins"
        )

    # =========================================================================
    # Helpers: Resources
    # =========================================================================

    @staticmethod
    def _load_jwks():
        jwks_path = os.path.join(
            testlib.get_resources_dir(), "jwt", "jwks.json"
        )
        with open(jwks_path, "r") as f:
            return json.load(f)

    @staticmethod
    def _load_tls_certs():
        resources = testlib.get_resources_dir()
        ca_path = os.path.join(resources, "oidc", "mock_ca.pem")
        cert_path = os.path.join(resources, "oidc", "mock_server.pem")
        key_path = os.path.join(resources, "oidc", "mock_server.key")
        with open(ca_path, "r") as f:
            ca_pem = f.read()
        return ca_path, ca_pem, cert_path, key_path

    # =========================================================================
    # Helpers: Configuration
    # =========================================================================

    def _configure_jwt_with_oidc(
        self,
        issuer_name,
        public_key_source,
        jwks=None,
        oidc_settings=None,
        issuer_overrides=None,
    ):
        issuer = {
            "name": issuer_name,
            "displayName": "Test OIDC Provider",
            "audienceHandling": "any",
            "subClaim": "sub",
            "audClaim": "aud",
            "audiences": [oidc_settings["clientId"]],
            "signingAlgorithm": "RS256",
            "jitProvisioning": True,
            "publicKeySource": public_key_source,
            "oidcSettings": oidc_settings,
        }
        if issuer_overrides:
            issuer.update(issuer_overrides)

        payload = {
            "enabled": True,
            "jwksUriRefreshIntervalS": 14400,
            "issuers": [issuer],
        }
        if public_key_source == "jwks":
            payload["issuers"][0]["jwks"] = jwks
        testlib.put_succ(self.cluster, "/settings/jwt", json=payload)

    def _configure_with_provider(
        self, node, provider, *, use_discovery=False, tls=None,
        issuer_overrides=None, post_logout_redirect_uris=_UNSET,
        oidc_overrides=None
    ):
        """Configure JWT/OIDC for a MockOIDCProvider instance.

        use_discovery=True switches to discovery URI mode (PAR flow is active
        for discovery mode since the mock advertises the PAR endpoint).
        tls is an optional dict of tlsVerifyPeer/tlsCa/tlsSni keys to merge
        into oidcSettings.
        post_logout_redirect_uris defaults to [node.url]; pass None (or []) to
        omit postLogoutRedirectUris entirely, exercising the default state where
        no post-logout redirect is configured (MB-72589).
        """
        oidc_settings = {
            "clientId": "oidc-client",
            "clientSecret": "oidc-secret",
            "baseRedirectUris": [node.url],
            "scopes": ["openid", "profile"],
            "nonceValidation": True,
            "pkceEnabled": True,
            "httpTimeoutMs": 5000,
            "tokenEndpointAuthMethod": "client_secret_post",
        }
        if post_logout_redirect_uris is _UNSET:
            oidc_settings["postLogoutRedirectUris"] = [node.url]
        elif post_logout_redirect_uris:
            oidc_settings["postLogoutRedirectUris"] = post_logout_redirect_uris
        if use_discovery:
            oidc_settings["endpointSource"] = "discovery"
            oidc_settings["oidcDiscoveryUri"] = provider.discovery_url
        else:
            oidc_settings["endpointSource"] = "manual"
            oidc_settings["authorizationEndpoint"] = provider.auth_url
            oidc_settings["tokenEndpoint"] = provider.token_url
            oidc_settings["endSessionEndpoint"] = provider.logout_url
        if tls:
            oidc_settings.update(tls)
        if oidc_overrides:
            oidc_settings.update(oidc_overrides)
        self._configure_jwt_with_oidc(
            issuer_name=provider.issuer,
            public_key_source="jwks_uri" if use_discovery else "jwks",
            jwks=None if use_discovery else provider.jwks,
            oidc_settings=oidc_settings,
            issuer_overrides=issuer_overrides,
        )

    # =========================================================================
    # Helpers: Login flows
    # =========================================================================

    def _oidc_ui_login(self, node, issuer_name, session, provider_verify=None):
        testlib.get_fail(
            node,
            "/pools/default",
            expected_code=401,
            headers=UI_HEADERS,
            session=session,
            auth=None,
        )

        r1 = testlib.get_succ(
            node,
            "/oidc/auth",
            expected_code=302,
            params={"issuer": issuer_name},
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
            auth=None,
        )
        provider_loc = r1.headers["Location"]
        assert not provider_loc.startswith(
            "/"
        ), f"Redirect failed: {provider_loc}"

        r2 = testlib.http_request(
            "GET",
            provider_loc,
            expected_code=302,
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
            verify=provider_verify,
        )

        r3 = testlib.http_request(
            "GET",
            r2.headers["Location"],
            expected_code=302,
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
        )
        assert "Location" in r3.headers

        testlib.get_succ(
            node,
            "/pools/default",
            expected_code=200,
            headers=UI_HEADERS,
            session=session,
            auth=None,
        )
        return True

    def _oidc_ui_logout(self, node, session, provider=None):
        r = testlib.get_succ(
            node,
            "/oidc/deauth",
            expected_code=302,
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
            auth=None,
        )
        loc = r.headers.get("Location")
        assert loc, "logout response missing Location header"

        if provider is not None:
            # RP-initiated logout must redirect to the OP end-session endpoint
            # carrying id_token_hint, so the IdP session is actually
            # terminated rather than just the local CB session.
            assert loc.startswith(provider.logout_url), loc
            assert "id_token_hint=" in loc, loc

        testlib.get_fail(
            node,
            "/pools/default",
            expected_code=401,
            headers=UI_HEADERS,
            session=session,
            auth=None,
        )
        return r

    def _oidc_auth_expect_login_failed(self, node, issuer_name, session):
        """Expect /oidc/auth to refuse to build a redirect to the IdP.

        The user is sent back to the UI with an error instead of to the IdP,
        and no session is established.
        """
        r = testlib.get_succ(
            node,
            "/oidc/auth",
            expected_code=302,
            params={"issuer": issuer_name},
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
            auth=None,
        )
        loc = r.headers["Location"]
        assert "oidcError=login_failed" in loc, \
            f"Expected the redirect to be refused, got: {loc}"

        testlib.get_fail(
            node,
            "/pools/default",
            expected_code=401,
            headers=UI_HEADERS,
            session=session,
            auth=None,
        )

    def _oidc_ui_login_expect_denied(self, node, issuer_name, session,
                                     expected_error="access_denied"):
        r1 = testlib.get_succ(
            node,
            "/oidc/auth",
            expected_code=302,
            params={"issuer": issuer_name},
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
            auth=None,
        )
        provider_loc = r1.headers["Location"]
        assert not provider_loc.startswith(
            "/"
        ), f"Redirect failed: {provider_loc}"

        r2 = testlib.http_request(
            "GET",
            provider_loc,
            expected_code=302,
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
        )

        r3 = testlib.http_request(
            "GET",
            r2.headers["Location"],
            expected_code=302,
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
        )
        loc = r3.headers.get("Location", "")
        assert f"oidcError={expected_error}" in loc, \
            f"Expected oidcError={expected_error} in Location: {loc}"

        testlib.get_fail(
            node,
            "/pools/default",
            expected_code=401,
            headers=UI_HEADERS,
            session=session,
            auth=None,
        )

    def _oidc_ui_login_expect_auth_denied(self, node, issuer_name, session):
        """Expect the callback to fail after the provider denies access.

        The provider redirects back with error=access_denied (RFC 6749
        §4.1.2.1). ns_server rejects the callback with 400 because 'code' is
        required by callback_validators().
        """
        testlib.get_fail(
            node,
            "/pools/default",
            expected_code=401,
            headers=UI_HEADERS,
            session=session,
            auth=None,
        )

        r1 = testlib.get_succ(
            node,
            "/oidc/auth",
            expected_code=302,
            params={"issuer": issuer_name},
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
            auth=None,
        )
        provider_loc = r1.headers["Location"]
        assert not provider_loc.startswith(
            "/"
        ), f"Redirect failed: {provider_loc}"

        r2 = testlib.http_request(
            "GET",
            provider_loc,
            expected_code=302,
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
        )
        cb_loc = r2.headers["Location"]
        assert "error=access_denied" in cb_loc, \
            f"Expected access_denied in callback: {cb_loc}"
        assert "state=" in cb_loc, \
            f"Expected state in callback: {cb_loc}"

        cb_path = cb_loc.replace(node.url, "")
        testlib.get_fail(
            node,
            cb_path,
            expected_code=400,
            headers=UI_HEADERS,
            allow_redirects=False,
            session=session,
            auth=None,
        )

        testlib.get_fail(
            node,
            "/pools/default",
            expected_code=401,
            headers=UI_HEADERS,
            session=session,
            auth=None,
        )

    # =========================================================================
    # Tests: /_ui/authMethods advertisement (no login flow required)
    # =========================================================================

    def authmethods_advertises_oidc_issuers_test(self):
        """OIDC-enabled issuers are advertised via /_ui/authMethods so the
        login page can render an SSO button per issuer. Non-OIDC (bearer-only)
        issuers are not browser-loginable and must be excluded."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        def oidc_settings():
            return {
                "clientId": "oidc-client",
                "clientSecret": "oidc-secret",
                "baseRedirectUris": [node.url],
                "endpointSource": "manual",
                "authorizationEndpoint": "https://idp.example.com/authorize",
                "tokenEndpoint": "https://idp.example.com/token",
                "scopes": ["openid", "profile"],
                "nonceValidation": True,
                "pkceEnabled": True,
                "httpTimeoutMs": 5000,
                "tokenEndpointAuthMethod": "client_secret_post",
                "postLogoutRedirectUris": [node.url],
            }

        def issuer(name, display_name, oidc=True):
            i = {
                "name": name,
                "audienceHandling": "any",
                "subClaim": "sub",
                "audClaim": "aud",
                "audiences": ["oidc-client"],
                "signingAlgorithm": "RS256",
                "publicKeySource": "jwks",
                "jwks": jwks,
            }
            if display_name is not None:
                i["displayName"] = display_name
            if oidc:
                i["oidcSettings"] = oidc_settings()
            return i

        # Nothing is advertised until an OIDC-enabled issuer is configured.
        # Deleting first keeps this independent of the order tests run in.
        testlib.ensure_deleted(self.cluster, "/settings/jwt")
        r = testlib.get_succ(
            self.cluster, "/_ui/authMethods", auth=None
        ).json()
        testlib.assert_eq(r["oidc"], [], name="oidc (none configured)")

        testlib.put_succ(
            self.cluster,
            "/settings/jwt",
            json={
                "enabled": True,
                "jwksUriRefreshIntervalS": 14400,
                "issuers": [
                    issuer("https://idp.example.com/a", "Provider A"),
                    issuer("https://idp.example.com/b", "Provider B"),
                    # Bearer-only issuer (no oidcSettings): must be excluded.
                    issuer("https://bearer.example.com", None, oidc=False),
                ],
            },
        )

        r = testlib.get_succ(
            self.cluster, "/_ui/authMethods", auth=None
        ).json()
        advertised = sorted(
            (e["name"], e["displayName"]) for e in r["oidc"]
        )
        testlib.assert_eq(
            advertised,
            [
                ("https://idp.example.com/a", "Provider A"),
                ("https://idp.example.com/b", "Provider B"),
            ],
            name="advertised oidc issuers",
        )

    # =========================================================================
    # Tests: Positive login flows
    # =========================================================================

    def login_failure_audit_test(self):
        """A failed OIDC login produces an audit record naming the reason.

        Event 8193 used to declare real_userid mandatory, and these paths have
        no identity to report, so memcached rejected every record and a failed
        SSO login left no audit trail at all (MB-73162).
        """
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()
        testlib.post_succ(self.cluster, "/settings/audit",
                          data={"auditdEnabled": "true"})
        try:
            with MockOIDCProvider(jwks, "oidc-client",
                                  "oidc-secret") as provider:
                # ns_server holds a secret the provider does not accept, so
                # the token exchange is refused and the login fails before any
                # ID token exists.
                self._configure_with_provider(
                    node, provider,
                    oidc_overrides={"clientSecret": "wrong-secret"})
                session = requests.Session()
                offset = testlib.audit_log_offset(node)
                self._oidc_ui_login_expect_denied(
                    node, provider.issuer, session,
                    expected_error="login_failed")
                event = testlib.wait_for_audit_event(node, 8193,
                                                     since_offset=offset)
                testlib.assert_eq(event.get("reason"),
                                  "token exchange failed", name="reason")
                testlib.assert_eq(event.get("type"), "oidc", name="type")
        finally:
            testlib.post_succ(self.cluster, "/settings/audit",
                              data={"auditdEnabled": "false"})

    def login_success_audit_test(self):
        """A successful OIDC login names the issuer and the claims.

        The callback used to discard the term jwt_auth built for a token that
        validated, so event 8192 carried only the roles the session ended up
        with and said nothing about where the session came from (MB-73162).

        The type is "jwt" rather than "oidc" because jwt_auth builds the term,
        for a browser login as much as for a bearer token.
        """
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()
        testlib.post_succ(self.cluster, "/settings/audit",
                          data={"auditdEnabled": "true"})
        try:
            with MockOIDCProvider(jwks, "oidc-client",
                                  "oidc-secret") as provider:
                self._configure_with_provider(node, provider)
                session = requests.Session()
                offset = testlib.audit_log_offset(node)
                self._oidc_ui_login(node, provider.issuer, session)
                event = testlib.wait_for_audit_event(node, 8192,
                                                     since_offset=offset)

                testlib.assert_eq(event.get("type"), "jwt", name="type")
                testlib.assert_eq(event.get("sub"), "testuser", name="sub")
                testlib.assert_eq(event.get("iss"), provider.issuer,
                                  name="iss")

                # The groups claim stays an array (MB-73360); mapped_groups is
                # the comma joined list get_authn_res_audit_props/1 builds.
                testlib.assert_eq(event.get("groups"), ["oidc_admins"],
                                  name="groups")
                testlib.assert_eq(event.get("mapped_groups"), "oidc_admins",
                                  name="mapped_groups")

                # roles is the mandatory field holding what RBAC granted, not
                # the claim the token carried, so login_success/1 must not
                # have overwritten it with the props.
                assert "admin" in event.get("roles", []), \
                    f"Expected admin in granted roles: {event.get('roles')}"

                self._oidc_ui_logout(node, session, provider)
        finally:
            testlib.post_succ(self.cluster, "/settings/audit",
                              data={"auditdEnabled": "false"})

    def access_denied_audit_test(self):
        """A login denied for want of privileges is audited with its claims.

        The token validates, so jwt_auth has built the full term by the time
        uilogin_phase2/4 rejects the session. That record is a login failure
        and should say which identity was refused, which is the question an
        operator has when an SSO user cannot get in (MB-73162).
        """
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()
        testlib.post_succ(self.cluster, "/settings/audit",
                          data={"auditdEnabled": "true"})
        try:
            with MockOIDCProvider(
                jwks, "oidc-client", "oidc-secret",
                token_groups=["oidc_nonadmins"],
            ) as provider:
                self._configure_with_provider(node, provider)
                session = requests.Session()
                offset = testlib.audit_log_offset(node)
                self._oidc_ui_login_expect_denied(node, provider.issuer,
                                                  session)
                event = testlib.wait_for_audit_event(node, 8193,
                                                     since_offset=offset)
                testlib.assert_eq(event.get("type"), "jwt", name="type")
                testlib.assert_eq(event.get("sub"), "testuser", name="sub")
                testlib.assert_eq(event.get("groups"), ["oidc_nonadmins"],
                                  name="groups")
        finally:
            testlib.post_succ(self.cluster, "/settings/audit",
                              data={"auditdEnabled": "false"})

    def oidc_login_basic_test(self):
        """Basic OIDC login with manually configured endpoints (air-gapped,
        plain HTTP)."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        with MockOIDCProvider(jwks, "oidc-client", "oidc-secret") as provider:
            self._configure_with_provider(node, provider)
            session = requests.Session()
            self._oidc_ui_login(node, provider.issuer, session)
            self._oidc_ui_logout(node, session, provider)

    def oidc_callback_form_post_test(self):
        """The callback is served on POST as well as on GET, for an IdP using
        the form_post response mode. Drive a real login but hand the
        authorization response back as a form body instead of a query string.
        """
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        with MockOIDCProvider(jwks, "oidc-client", "oidc-secret") as provider:
            self._configure_with_provider(node, provider)
            session = requests.Session()

            r1 = testlib.get_succ(
                node,
                "/oidc/auth",
                expected_code=302,
                params={"issuer": provider.issuer},
                headers=UI_HEADERS,
                allow_redirects=False,
                session=session,
                auth=None,
            )
            r2 = testlib.http_request(
                "GET",
                r1.headers["Location"],
                expected_code=302,
                headers=UI_HEADERS,
                allow_redirects=False,
                session=session,
            )
            callback = urllib.parse.urlparse(r2.headers["Location"])
            params = urllib.parse.parse_qs(callback.query)

            testlib.post_succ(
                node,
                callback.path,
                expected_code=302,
                data={"code": params["code"][0],
                      "state": params["state"][0]},
                headers=UI_HEADERS,
                allow_redirects=False,
                session=session,
                auth=None,
            )

            testlib.get_succ(
                node,
                "/pools/default",
                expected_code=200,
                headers=UI_HEADERS,
                session=session,
                auth=None,
            )
            self._oidc_ui_logout(node, session, provider)

    def _oidc_login_signed_with(self, alg):
        """Run a full browser login with the ID token signed using alg.

        Regression for MB-73161: at_hash has to be verified with the digest
        named by the ID token's alg header, truncated to half of its length,
        so 24 bytes for RS384 and 32 for RS512. Verifying it as SHA-256
        refuses the login with bad_access_token_hash.

        The JWKS key advertises alg so the published key set and the ID token
        agree, the way an IdP configured for that algorithm publishes it.
        """
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()
        for key in jwks["keys"]:
            if key["kty"] == "RSA":
                key["alg"] = alg

        with MockOIDCProvider(
            jwks, "oidc-client", "oidc-secret", id_token_alg=alg
        ) as provider:
            self._configure_with_provider(
                node, provider, issuer_overrides={"signingAlgorithm": alg}
            )
            session = requests.Session()
            self._oidc_ui_login(node, provider.issuer, session)
            self._oidc_ui_logout(node, session, provider)

    def oidc_login_rs384_test(self):
        """OIDC login with an ID token signed RS384 (SHA-384 at_hash)."""
        self._oidc_login_signed_with("RS384")

    def oidc_login_rs512_test(self):
        """OIDC login with an ID token signed RS512 (SHA-512 at_hash)."""
        self._oidc_login_signed_with("RS512")

    def oidc_logout_no_post_logout_redirect_test(self):
        """Regression for MB-72589: RP-initiated logout must succeed when
        postLogoutRedirectUris is not configured (the default state).

        Previously /oidc/deauth returned HTTP 400 ("No configured redirect base
        matches host") in this case, destroying the local CB session but
        leaving the IdP session alive. Logout must still redirect to the OP
        end-session endpoint with id_token_hint, and must not carry a
        post_logout_redirect_uri since none is configured."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        with MockOIDCProvider(jwks, "oidc-client", "oidc-secret") as provider:
            self._configure_with_provider(
                node, provider, post_logout_redirect_uris=None
            )
            session = requests.Session()
            self._oidc_ui_login(node, provider.issuer, session)
            r = self._oidc_ui_logout(node, session, provider)
            assert "post_logout_redirect_uri" not in r.headers["Location"], (
                r.headers["Location"]
            )

    def oidc_uilogout_contract_test(self):
        """The UI logs out via an ajax POST /uilogout. For an OIDC session the
        server must reply 400 + {redirect: /oidc/deauth} rather than 302ing
        directly to the IdP: an XMLHttpRequest would auto-follow a 302
        cross-origin instead of performing a top-level browser navigation, so
        RP-initiated logout would fail from the real UI. The UI reads the
        redirect from the body and navigates to /oidc/deauth, which completes
        logout. Mirrors SAML's POST /uilogout handling."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        with MockOIDCProvider(jwks, "oidc-client", "oidc-secret") as provider:
            self._configure_with_provider(node, provider)
            session = requests.Session()
            self._oidc_ui_login(node, provider.issuer, session)

            r = testlib.post_succ(
                node,
                "/uilogout",
                expected_code=400,
                headers=UI_HEADERS,
                allow_redirects=False,
                session=session,
                auth=None,
            )
            body = r.json()
            assert body.get("redirect") == "/oidc/deauth", body

            # The session is still alive until /oidc/deauth is hit, and that
            # endpoint then 302s the browser to the IdP end-session endpoint.
            self._oidc_ui_logout(node, session, provider)

    def oidc_login_discovery_test(self):
        """OIDC login via discovery URI (plain HTTP). PAR is active because the
        mock advertises pushed_authorization_request_endpoint."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        with MockOIDCProvider(jwks, "oidc-client", "oidc-secret") as provider:
            self._configure_with_provider(node, provider, use_discovery=True)
            session = requests.Session()
            testlib.poll_for_condition(
                lambda: self._oidc_ui_login(node, provider.issuer, session),
                sleep_time=0.5,
                timeout=60,
                retry_on_assert=True,
            )
            self._oidc_ui_logout(node, session, provider)

    def oidc_login_airgapped_tls_test(self):
        """Air-gapped OIDC login against an HTTPS IdP (TLS verified)."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()
        ca_path, ca_pem, cert_path, key_path = self._load_tls_certs()
        tls = {"tlsVerifyPeer": True, "tlsCa": ca_pem, "tlsSni": "localhost"}

        with MockOIDCProvider(
            jwks, "oidc-client", "oidc-secret",
            use_tls=True, tls_certfile=cert_path, tls_keyfile=key_path,
        ) as provider:
            self._configure_with_provider(node, provider, tls=tls)
            session = requests.Session()
            self._oidc_ui_login(
                node, provider.issuer, session, provider_verify=ca_path
            )
            self._oidc_ui_logout(node, session, provider)

    def oidc_login_discovery_tls_test(self):
        """Discovery OIDC login + PAR against an HTTPS IdP (TLS verified).
        Exercises the path fixed by MB-72541 (TLS options threaded through PAR
        requests)."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()
        ca_path, ca_pem, cert_path, key_path = self._load_tls_certs()
        tls = {"tlsVerifyPeer": True, "tlsCa": ca_pem, "tlsSni": "localhost"}

        with MockOIDCProvider(
            jwks, "oidc-client", "oidc-secret",
            use_tls=True, tls_certfile=cert_path, tls_keyfile=key_path,
        ) as provider:
            self._configure_with_provider(
                node, provider,
                use_discovery=True,
                tls=tls,
                issuer_overrides={
                    "jwksUriTlsVerifyPeer": True,
                    "jwksUriTlsCa": ca_pem,
                    "jwksUriTlsSni": "localhost",
                },
            )
            session = requests.Session()
            testlib.poll_for_condition(
                lambda: self._oidc_ui_login(
                    node, provider.issuer, session, provider_verify=ca_path
                ),
                sleep_time=0.5,
                timeout=60,
                retry_on_assert=True,
            )
            self._oidc_ui_logout(node, session, provider)

    # =========================================================================
    # Tests: Negative cases
    # =========================================================================

    def oidc_discovery_tls_verify_peer_after_unverified_test(self):
        """Negative case: turning tlsVerifyPeer on must reject an IdP whose CA
        is not trusted, even after an unverified login to the same IdP.

        The HTTP client pools connections per host and port and does not
        consider the TLS options of the request it is about to send, so a
        connection opened while verification was off would satisfy a later
        request that asks for it, and the certificate would never be checked.
        """
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()
        ca_path, ca_pem, cert_path, key_path = self._load_tls_certs()

        with MockOIDCProvider(
            jwks, "oidc-client", "oidc-secret",
            use_tls=True, tls_certfile=cert_path, tls_keyfile=key_path,
        ) as provider:
            # Log in with verification off. This is what leaves a usable
            # connection to the IdP behind.
            self._configure_with_provider(
                node, provider,
                use_discovery=True,
                tls={"tlsVerifyPeer": False},
                issuer_overrides={"jwksUriTlsVerifyPeer": False},
            )
            session = requests.Session()
            testlib.poll_for_condition(
                lambda: self._oidc_ui_login(
                    node, provider.issuer, session, provider_verify=ca_path
                ),
                sleep_time=0.5,
                timeout=60,
                retry_on_assert=True,
            )
            self._oidc_ui_logout(node, session, provider)

            # Same issuer, verification on, but the CA of the IdP is not
            # supplied, so its certificate cannot be trusted.
            self._configure_with_provider(
                node, provider,
                use_discovery=True,
                tls={"tlsVerifyPeer": True, "tlsSni": "localhost"},
                issuer_overrides={
                    "jwksUriTlsVerifyPeer": True,
                    "jwksUriTlsSni": "localhost",
                },
            )
            self._oidc_auth_expect_login_failed(
                node, provider.issuer, requests.Session()
            )

            # And it recovers once the CA is trusted, so the rejection above
            # is the certificate check and not a wedged provider worker.
            self._configure_with_provider(
                node, provider,
                use_discovery=True,
                tls={"tlsVerifyPeer": True, "tlsCa": ca_pem,
                     "tlsSni": "localhost"},
                issuer_overrides={
                    "jwksUriTlsVerifyPeer": True,
                    "jwksUriTlsCa": ca_pem,
                    "jwksUriTlsSni": "localhost",
                },
            )
            session = requests.Session()
            testlib.poll_for_condition(
                lambda: self._oidc_ui_login(
                    node, provider.issuer, session, provider_verify=ca_path
                ),
                sleep_time=0.5,
                timeout=60,
                retry_on_assert=True,
            )
            self._oidc_ui_logout(node, session, provider)

    def oidc_authorization_denied_test(self):
        """Negative case: IdP denies authorization; user is never authenticated.

        The provider returns error=access_denied in the callback redirect.
        ns_server rejects the callback with 400 because 'code' is required.
        """
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        with MockOIDCProvider(
            jwks, "oidc-client", "oidc-secret", deny_auth=True
        ) as provider:
            self._configure_with_provider(node, provider)
            session = requests.Session()
            self._oidc_ui_login_expect_auth_denied(
                node, provider.issuer, session
            )

    def oidc_login_insufficient_permissions_test(self):
        """Negative case: JWT validates but user has no mapped privileges."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        with MockOIDCProvider(
            jwks, "oidc-client", "oidc-secret",
            token_groups=["oidc_nonadmins"],
        ) as provider:
            self._configure_with_provider(node, provider)
            session = requests.Session()
            self._oidc_ui_login_expect_denied(node, provider.issuer, session)

    def oidc_callback_unknown_state_test(self):
        """The state parameter is the CSRF guard: the callback proceeds only
        for a state held in the pre-auth store. An unknown or expired state
        sends the browser back to the UI with login_failed and establishes no
        session."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        with MockOIDCProvider(jwks, "oidc-client", "oidc-secret") as provider:
            self._configure_with_provider(node, provider)
            session = requests.Session()

            r = testlib.get_succ(
                node,
                "/oidc/callback",
                expected_code=302,
                params={"code": "unused", "state": "not-a-known-state"},
                headers=UI_HEADERS,
                allow_redirects=False,
                session=session,
                auth=None,
            )
            loc = r.headers["Location"]
            assert "oidcError=login_failed" in loc, loc

            testlib.get_fail(
                node,
                "/pools/default",
                expected_code=401,
                headers=UI_HEADERS,
                session=session,
                auth=None,
            )

    def oidc_auth_ineligible_issuer_test(self):
        """Negative case: /oidc/auth refuses to start a login for an issuer it
        cannot use. One is not configured at all, the other is configured
        without oidcSettings, meaning bearer token validation only and no
        browser login."""
        node = self.cluster.connected_nodes[0]
        jwks = self._load_jwks()

        testlib.put_succ(
            self.cluster,
            "/settings/jwt",
            json={
                "enabled": True,
                "jwksUriRefreshIntervalS": 14400,
                "issuers": [
                    {
                        "name": "https://bearer.example.com",
                        "audienceHandling": "any",
                        "subClaim": "sub",
                        "audClaim": "aud",
                        "audiences": ["oidc-client"],
                        "signingAlgorithm": "RS256",
                        "publicKeySource": "jwks",
                        "jwks": jwks,
                    }
                ],
            },
        )

        for issuer_name in ["https://not-configured.example.com",
                            "https://bearer.example.com"]:
            testlib.get_fail(
                node,
                "/oidc/auth",
                expected_code=400,
                params={"issuer": issuer_name},
                headers=UI_HEADERS,
                allow_redirects=False,
                auth=None,
            )
