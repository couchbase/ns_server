# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in
# the file licenses/APL2.txt.
"""End-to-end tests for the credential store."""

import os
import time
import testlib
import requests

from testsets.users_tests import put_user, build_payload


# ---------------------------------------------------------------------------
# Test certificate/key data (loaded from cluster_tests/resources/test_certs)
# ---------------------------------------------------------------------------

def _load_test_cert(filename):
    """Load a test certificate or key from the resources directory."""
    resources_dir = os.path.join(os.path.dirname(__file__),
                                 '..', 'resources', 'test_certs')
    with open(os.path.join(resources_dir, filename), 'r') as f:
        return f.read()


# Valid certificate and private key for validation tests.
VALID_CERT_PEM = _load_test_cert('test_CA.pem')
VALID_PKEY_PEM = _load_test_cert('test_CA.pkey')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CREDS_BASE = "/settings/credentials"
CREDS_STORE = "/settings/credentialStore"
CBAUTH_BASE = "/_cbauth/getCredential"
ENCR_AT_REST_CONFIG = "/settings/security/encryptionAtRest/config"

# Test users created for RBAC tests (cleaned up in test_teardown).
TEST_CONSUMER_USER = "test_cred_consumer"
TEST_CONSUMER_PASSWORD = "password123!"

# Service users that need credential_consumer to consume
# credentials (the admin role no longer grants consume).
# These are the user-facing service names used in the REST
# endpoint: /settings/rbac/services/<name>/roles
SERVICE_CONSUMER_USERS = ["backup", "index", "n1ql"]

# A minimal valid AWS credential body.
def aws_body(suffix="", key_id="AKIAIOSFODNN7EXAMPLE",
             secret="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
             region="us-east-1"):
    return {
        "type": "aws",
        "fields": {
            "accessKeyId": key_id,
            "secretAccessKey": secret,
            "region": region,
        }
    }


def azure_shared_body():
    return {
        "type": "azureShared",
        "fields": {
            "accountName": "myaccount",
            "accountKey": "dGVzdGtleQ==",
        }
    }


def azure_ad_body():
    return {
        "type": "azureAd",
        "fields": {
            "clientId": "00000000-0000-0000-0000-000000000000",
            "tenantId": "11111111-1111-1111-1111-111111111111",
            "clientSecret": "super-secret-client-value",
        }
    }


def azure_sas_body():
    return {
        "type": "azureSas",
        "fields": {
            "accountName": "myaccount",
            "sharedAccessSignature": "sv=2020-08-04&ss=b&srt=sco&sig=XXXX",
        }
    }


def azure_managed_body():
    return {
        "type": "azureManaged",
        "fields": {
            "managedIdentityId": "22222222-2222-2222-2222-222222222222",
        }
    }


def gcp_body():
    return {
        "type": "gcp",
        "fields": {
            "jsonCredentials": '{"type":"service_account","project_id":"p"}',
        }
    }



def http_body():
    return {
        "type": "http",
        "fields": {
            "authScheme": "bearer",
            "token": "sk_live_secret_token",
            "headerName": "Authorization",
        }
    }


def couchbase_body():
    return {
        "type": "couchbase",
        "fields": {
            "encryptionType": "none",
            "username": "admin",
            "password": "s3cret",
        }
    }



# Mapping of credential type name to:
#   (body_builder, sensitive_fields, non_sensitive_fields)
# sensitive_fields are expected to be masked ("********") in public GET;
# non_sensitive_fields are expected to be returned as-is.
ALL_CRED_TYPES = {
    "aws": (aws_body,
            ["secretAccessKey"],
            {"accessKeyId": "AKIAIOSFODNN7EXAMPLE",
             "region": "us-east-1"}),
    "azureShared": (azure_shared_body,
                     ["accountKey"],
                     {"accountName": "myaccount"}),
    "azureAd": (azure_ad_body,
                 ["clientSecret"],
                 {"clientId": "00000000-0000-0000-0000-000000000000",
                  "tenantId": "11111111-1111-1111-1111-111111111111"}),
    "azureSas": (azure_sas_body,
                  ["sharedAccessSignature"],
                  {"accountName": "myaccount"}),
    "azureManaged": (azure_managed_body,
                      [],
                      {"managedIdentityId":
                       "22222222-2222-2222-2222-222222222222"}),
    "gcp": (gcp_body,
            ["jsonCredentials"],
            {}),
    "http": (http_body,
             ["token"],
             {"authScheme": "bearer",
              "headerName": "Authorization"}),
    "couchbase": (couchbase_body,
                  ["password"],
                  {"encryptionType": "none",
                   "username": "admin"}),
}


def cred_url(cred_id):
    return f"{CREDS_BASE}/{cred_id}"


def list_credentials(response_json):
    """Extract the credentials list from a list response.

    The GET /settings/credentials response is an object:
        {"warnings": [...], "credentials": [...]}
    """
    return response_json.get("credentials", [])


def list_warnings(response_json):
    """Extract the warnings list from a list response."""
    return response_json.get("warnings", [])


def get_cbauth_error(response_json):
    """Extract error code and reason from cbauth error response.

    The cbauth endpoint returns errors in the format:
        {"error": {"code": "ERROR_CODE", "reason": "Human-readable message"}}

    Returns:
        (code, reason) tuple, or (None, None) if not an error response.
    """
    err = response_json.get("error")
    if isinstance(err, dict):
        return err.get("code", ""), err.get("reason", "")
    return None, None


def cbauth_url(cred_id):
    return f"{CBAUTH_BASE}/{cred_id}"


def get_special_password(node):
    """Retrieve the internal special password used by @-prefixed service
    users (e.g. @ns_server, @backup, @cbq-engine).  Same mechanism as
    internal_creds_rotation_tests.get_pass()."""
    r = testlib.post_succ(node, '/diag/eval',
                          data='ns_config_auth:get_password(special).')
    return r.text.strip('"')


def cbauth_get(node, cred_id, auth,
               on_behalf_user=None, on_behalf_domain=None):
    """Issue a GET to /_cbauth/getCredential/<id> with on-behalf-of params.

    This mirrors what cbauth's Creds.GetCredential() does: the service
    authenticates via Basic Auth (auth tuple) and passes the end-user
    identity as query parameters (user, domain).

    The service guardrail is enforced by the server based on the
    authenticated identity of the caller (e.g. @backup → backup,
    @cbq-engine → n1ql), not the User-Agent header.

    Args:
        node: cluster node to hit
        cred_id: credential ID (may contain '/')
        auth: (username, password) tuple — the *service* identity
        on_behalf_user: the end-user name (e.g. "Administrator" or "@backup")
        on_behalf_domain: the end-user domain (e.g. "admin" or "local")

    Returns:
        requests.Response
    """
    url = node.url + cbauth_url(cred_id)
    params = {}
    if on_behalf_user is not None:
        params["user"] = on_behalf_user
    if on_behalf_domain is not None:
        params["domain"] = on_behalf_domain
    return requests.get(url, auth=auth,
                        params=params, timeout=10)


def create_consumer_user(cluster, username, password, credential_pattern):
    """Create a local user with credential_consumer role for the given
    credential ID or pattern (e.g. 'test/aws/prod' or 'test/*')."""
    role = f"credential_consumer[{credential_pattern}]"
    put_user(cluster, 'local', username, password=password, roles=role)


def delete_consumer_user(cluster, username):
    """Best-effort delete of a local test user."""
    testlib.ensure_deleted(
        cluster, f'/settings/rbac/users/local/{username}')


def ensure_config_encryption_enabled(cluster):
    """Ensure config encryption at rest is enabled (nodeSecretManager).

    A previous testset running on the same shared cluster may have explicitly
    disabled config encryption (e.g. NativeEncryptionPermissionsTests).  The
    credential store requires it, so we re-enable it before running our tests.
    """
    testlib.post_succ(cluster, ENCR_AT_REST_CONFIG,
                      json={"encryptionMethod": "nodeSecretManager",
                            "encryptionKeyId": -1,
                            "skipEncryptionKeyTest": False})

def grant_service_consumer_role(cluster, service_name,
                                pattern="*"):
    """Grant credential_consumer role to a service
    via PUT /settings/rbac/services/<name>/roles."""
    role = f"credential_consumer[{pattern}]"
    testlib.put_succ(
        cluster,
        f'/settings/rbac/services/{service_name}/roles',
        data={'roles': role})


def delete_service_consumer_role(cluster, service_name):
    """Best-effort delete of a service role grant."""
    testlib.ensure_deleted(
        cluster,
        f'/settings/rbac/services/{service_name}/roles')


# ---------------------------------------------------------------------------
# 1. CRUD
# ---------------------------------------------------------------------------

class CredentialStoreCrudTests(testlib.BaseTestSet):
    """Basic CRUD lifecycle, redaction, and per-type smoke tests for the
    credential store."""

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise",
                                           encryption=True)

    def setup(self):
        ensure_config_encryption_enabled(self.cluster)
        self.node = self.cluster.connected_nodes[0]
        self.special_password = get_special_password(self.node)
        for svc in SERVICE_CONSUMER_USERS:
            grant_service_consumer_role(self.cluster, svc)

    def teardown(self):
        for svc in SERVICE_CONSUMER_USERS:
            delete_service_consumer_role(self.cluster, svc)

    def test_teardown(self):
        cleanup_ids = ["test/aws/e2e", "test/aws/update", "test/aws/delete"]
        for type_name in ALL_CRED_TYPES:
            cleanup_ids.append(f"test/{type_name}/e2e")
        for cred_id in cleanup_ids:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def crud_lifecycle_test(self):
        cred_id = "test/aws/e2e"
        body = aws_body()

        # --- CREATE ---
        r = testlib.post_succ(self.cluster, cred_url(cred_id),
                              json=body, expected_code=201)
        j = r.json()
        testlib.assert_eq(j["id"], cred_id, "id after create")
        testlib.assert_eq(j["type"], "aws", "type after create")
        fields = j["fields"]
        testlib.assert_eq(fields["accessKeyId"], "AKIAIOSFODNN7EXAMPLE",
                          "accessKeyId after create")
        # secretAccessKey must be present and masked in the public response
        assert "secretAccessKey" in fields, \
            f"secretAccessKey must be present in public response: {fields}"
        testlib.assert_eq(fields["secretAccessKey"], "********",
                          "secretAccessKey must be masked in public response")

        # --- GET ---
        r = testlib.get_succ(self.cluster, cred_url(cred_id))
        j = r.json()
        testlib.assert_eq(j["id"], cred_id, "id after get")
        fields = j["fields"]
        assert "secretAccessKey" in fields, \
            "secretAccessKey must be present in GET response"
        testlib.assert_eq(fields["secretAccessKey"], "********",
                          "secretAccessKey must be masked in GET response")

        # --- LIST ---
        r = testlib.get_succ(self.cluster, CREDS_BASE)
        creds = list_credentials(r.json())
        ids = [c["id"] for c in creds]
        assert cred_id in ids, \
            f"Created cred {cred_id!r} missing from list"

        # --- LIST with prefix ---
        r = testlib.get_succ(self.cluster,
                             CREDS_BASE + "?prefix=test/aws")
        creds = list_credentials(r.json())
        ids = [c["id"] for c in creds]
        assert cred_id in ids, \
            "Prefix-filtered list missing credential"

        r = testlib.get_succ(self.cluster,
                             CREDS_BASE + "?prefix=other/prefix")
        creds = list_credentials(r.json())
        assert creds == [], \
            "Prefix filter should have returned empty list"

        # --- UPDATE ---
        updated_body = aws_body(key_id="NEWKEYID000000000000",
                                secret="NEWsecret",
                                region="eu-west-1")
        r = testlib.put_succ(self.cluster, cred_url(cred_id), json=updated_body)
        j = r.json()
        testlib.assert_eq(j["fields"]["accessKeyId"], "NEWKEYID000000000000",
                          "accessKeyId after update")
        assert "secretAccessKey" in j["fields"], \
            "secretAccessKey must be present in PUT response"
        testlib.assert_eq(j["fields"]["secretAccessKey"], "********",
                          "secretAccessKey must be masked in PUT response")

        # --- DELETE ---
        testlib.delete_succ(self.cluster, cred_url(cred_id))
        testlib.get_fail(self.cluster, cred_url(cred_id), 404)

    def duplicate_create_test(self):
        cred_id = "test/aws/e2e"
        body = aws_body()
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=body, expected_code=201)
        try:
            testlib.post_fail(self.cluster, cred_url(cred_id),
                              409, json=body)
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def not_found_test(self):
        testlib.get_fail(self.cluster, cred_url("does/not/exist"), 404)
        testlib.delete_fail(self.cluster, cred_url("does/not/exist"), 404)

    def put_type_change_rejected_test(self):
        """PUT must reject a request that changes the credential's type with
        a 400, not surface a 500."""
        cred_id = "test/aws/type-change"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            r = testlib.put_fail(self.cluster, cred_url(cred_id), 400,
                                 json=gcp_body())
            assert "error" in r.json(), \
                f"Expected error body, got {r.text!r}"
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def cbauth_not_found_test(self):
        backup_auth = ("@backup", self.special_password)
        r = cbauth_get(self.node, "does/not/exist", auth=backup_auth,
                       on_behalf_user="@backup",
                       on_behalf_domain="admin")
        testlib.assert_http_code(404, r)

    def all_credential_types_test(self):
        """Create one credential for every supported type and verify:
        - POST 201 succeeds
        - Public GET masks all sensitive fields to "********"
        - Public GET returns non-sensitive fields as-is
        - cbauth path returns plaintext for all sensitive fields
        - DELETE cleans up
        """
        for type_name, (body_fn, sensitive, non_sensitive) in \
                ALL_CRED_TYPES.items():
            cred_id = f"test/{type_name}/e2e"
            body = body_fn()
            try:
                # --- CREATE ---
                r = testlib.post_succ(self.cluster, cred_url(cred_id),
                                      json=body, expected_code=201)
                j = r.json()
                testlib.assert_eq(j["id"], cred_id,
                                  f"id after create ({type_name})")
                testlib.assert_eq(j["type"], type_name,
                                  f"type after create ({type_name})")

                # --- Public GET: sensitive masked, non-sensitive as-is ---
                r = testlib.get_succ(self.cluster, cred_url(cred_id))
                fields = r.json()["fields"]
                for sf in sensitive:
                    assert sf in fields, \
                        (f"{type_name}: sensitive field {sf!r} must be "
                         f"present in GET response: {fields}")
                    testlib.assert_eq(
                        fields[sf], "********",
                        f"{type_name}: {sf} must be masked in public GET")
                for key, expected in non_sensitive.items():
                    testlib.assert_eq(
                        fields[key], expected,
                        f"{type_name}: {key} in public GET")

                # --- cbauth path: sensitive fields in plaintext ---
                backup_auth = ("@backup", self.special_password)
                r = cbauth_get(self.node, cred_id, auth=backup_auth,
                               on_behalf_user="@backup",
                               on_behalf_domain="admin")
                testlib.assert_http_code(200, r)
                cb_fields = r.json()["fields"]
                for sf in sensitive:
                    assert sf in cb_fields, \
                        (f"{type_name}: sensitive field {sf!r} must be "
                         f"present in cbauth response: {cb_fields}")
                    assert cb_fields[sf] != "********", \
                        (f"{type_name}: {sf} must NOT be masked in cbauth "
                         f"response, got {cb_fields[sf]!r}")
                    # Verify the value matches what was sent.
                    testlib.assert_eq(
                        cb_fields[sf], body["fields"][sf],
                        f"{type_name}: {sf} plaintext in cbauth")
                for key, expected in non_sensitive.items():
                    testlib.assert_eq(
                        cb_fields[key], expected,
                        f"{type_name}: {key} in cbauth")

            finally:
                testlib.ensure_deleted(self.cluster, cred_url(cred_id))


# ---------------------------------------------------------------------------
# 2. Guardrails
# ---------------------------------------------------------------------------

class CredentialGuardrailsTests(testlib.BaseTestSet):
    """Guardrail validation, persistence, and enforcement tests."""

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise",
                                           encryption=True)

    def setup(self):
        ensure_config_encryption_enabled(self.cluster)
        self.node = self.cluster.connected_nodes[0]
        self.special_password = get_special_password(self.node)
        for svc in SERVICE_CONSUMER_USERS:
            grant_service_consumer_role(self.cluster, svc)

    def teardown(self):
        for svc in SERVICE_CONSUMER_USERS:
            delete_service_consumer_role(self.cluster, svc)

    def test_teardown(self):
        cleanup_ids = ["test/guardrails/e2e",
                       "test/guardrails/invalid",
                       "test/guardrails/backup_only",
                       "test/guardrails/no_services",
                       "test/guardrails/n1ql_consumer",
                       "test/guardrails/n1ql_only",
                       "test/guardrails/full_admin",
                       "test/guardrails/url_whitelist",
                       "test/consume/backup_e2e"]
        for cred_id in cleanup_ids:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))
        delete_consumer_user(self.cluster, TEST_CONSUMER_USER)

    def guardrails_create_and_retrieve_test(self):
        """Create a credential with all guardrail types including urlWhitelist,
        verify they are persisted and returned in both public GET and cbauth
        path."""
        cred_id = "test/guardrails/e2e"
        body = aws_body()
        body["guardrails"] = {
            "allowedServices": ["n1ql", "backup"],
            "urlWhitelist": {
                "allAccess": False,
                "allowedUrls": ["https://api.example.com/v1"],
                "disallowedUrls": ["https://evil.example.com"],
            },
            "allowedResources": ["bucket/backup-data"],
            "allowedOperations": ["READ", "LIST"],
        }
        body["description"] = "guardrails test credential"

        try:
            # --- CREATE ---
            r = testlib.post_succ(self.cluster, cred_url(cred_id),
                                  json=body, expected_code=201)
            j = r.json()
            testlib.assert_eq(j["id"], cred_id, "id after create")

            # --- Public GET: guardrails in meta ---
            r = testlib.get_succ(self.cluster, cred_url(cred_id))
            j = r.json()
            meta = j["meta"]
            assert "guardrails" in meta, \
                f"guardrails key missing from meta: {meta}"
            gr = meta["guardrails"]
            testlib.assert_eq(sorted(gr["allowedServices"]),
                              ["backup", "n1ql"],
                              "allowedServices in public GET")
            # urlWhitelist is a nested object
            assert "urlWhitelist" in gr, \
                f"urlWhitelist key missing from guardrails: {gr}"
            wl = gr["urlWhitelist"]
            testlib.assert_eq(wl["allAccess"], False,
                              "allAccess in public GET")
            testlib.assert_eq(wl["allowedUrls"],
                              ["https://api.example.com/v1"],
                              "allowedUrls in public GET")
            testlib.assert_eq(wl["disallowedUrls"],
                              ["https://evil.example.com"],
                              "disallowedUrls in public GET")
            testlib.assert_eq(gr["allowedResources"],
                              ["bucket/backup-data"],
                              "allowedResources in public GET")
            testlib.assert_eq(gr["allowedOperations"],
                              ["READ", "LIST"],
                              "allowedOperations in public GET")

            # description should be in meta too
            testlib.assert_eq(meta.get("description"),
                              "guardrails test credential",
                              "description in public GET")

            # --- cbauth path: guardrails also present ---
            # The service authenticates as @backup, which maps to the
            # 'backup' service — matching the allowedServices guardrail.
            backup_auth = ("@backup", self.special_password)
            r = cbauth_get(self.node, cred_id, auth=backup_auth,
                           on_behalf_user="@backup",
                           on_behalf_domain="admin")
            testlib.assert_http_code(200, r)
            cb_meta = r.json()["meta"]
            assert "guardrails" in cb_meta, \
                f"guardrails key missing from cbauth meta: {cb_meta}"
            cb_gr = cb_meta["guardrails"]
            testlib.assert_eq(sorted(cb_gr["allowedServices"]),
                              ["backup", "n1ql"],
                              "allowedServices in cbauth")
            assert "urlWhitelist" in cb_gr, \
                f"urlWhitelist missing from cbauth guardrails: {cb_gr}"
            cb_wl = cb_gr["urlWhitelist"]
            testlib.assert_eq(cb_wl["allAccess"], False,
                              "allAccess in cbauth")
            testlib.assert_eq(cb_wl["allowedUrls"],
                              ["https://api.example.com/v1"],
                              "allowedUrls in cbauth")
            testlib.assert_eq(cb_wl["disallowedUrls"],
                              ["https://evil.example.com"],
                              "disallowedUrls in cbauth")
            testlib.assert_eq(cb_gr["allowedResources"],
                              ["bucket/backup-data"],
                              "allowedResources in cbauth")
            testlib.assert_eq(cb_gr["allowedOperations"],
                              ["READ", "LIST"],
                              "allowedOperations in cbauth")

        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def guardrails_invalid_service_test(self):
        """Creating a credential with an unknown service name in
        allowedServices must fail validation."""
        cred_id = "test/guardrails/invalid"
        body = aws_body()
        body["guardrails"] = {
            "allowedServices": ["not_a_real_service"],
        }
        testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)

    def guardrails_update_test(self):
        """Guardrails can be added/changed via PUT."""
        cred_id = "test/guardrails/e2e"
        body = aws_body()
        try:
            testlib.post_succ(self.cluster, cred_url(cred_id),
                              json=body, expected_code=201)

            # Initial GET: no guardrails
            r = testlib.get_succ(self.cluster, cred_url(cred_id))
            meta = r.json()["meta"]
            # guardrails key may be absent or empty
            gr = meta.get("guardrails", {})
            assert not gr or all(not v for v in gr.values()), \
                f"Expected no guardrails initially, got: {gr}"

            # PUT with guardrails
            updated = aws_body()
            updated["guardrails"] = {
                "allowedServices": ["fts"],
                "allowedOperations": ["WRITE"],
            }
            testlib.put_succ(self.cluster, cred_url(cred_id), json=updated)

            # GET and verify guardrails are present
            r = testlib.get_succ(self.cluster, cred_url(cred_id))
            gr = r.json()["meta"]["guardrails"]
            testlib.assert_eq(gr["allowedServices"], ["fts"],
                              "allowedServices after update")
            testlib.assert_eq(gr["allowedOperations"], ["WRITE"],
                              "allowedOperations after update")

        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def guardrails_empty_arrays_rejected_test(self):
        """Empty guardrail arrays and empty urlWhitelist sub-objects
        must be rejected with 400."""
        cred_id = "test/guardrails/e2e"

        # Empty allowedResources
        body = aws_body()
        body["guardrails"] = {
            "allowedServices": ["n1ql"],
            "allowedResources": [],
        }
        testlib.post_fail(self.cluster, cred_url(cred_id),
                          400, json=body)

        # Empty allowedOperations
        body = aws_body()
        body["guardrails"] = {
            "allowedServices": ["n1ql"],
            "allowedOperations": [],
        }
        testlib.post_fail(self.cluster, cred_url(cred_id),
                          400, json=body)

        # Empty allowedServices
        body = aws_body()
        body["guardrails"] = {"allowedServices": []}
        testlib.post_fail(self.cluster, cred_url(cred_id),
                          400, json=body)

        # Empty urlWhitelist sub-object
        body = aws_body()
        body["guardrails"] = {
            "allowedServices": ["n1ql"],
            "urlWhitelist": {},
        }
        testlib.post_fail(self.cluster, cred_url(cred_id),
                          400, json=body)

        # Empty allowedUrls inside urlWhitelist
        body = aws_body()
        body["guardrails"] = {
            "allowedServices": ["n1ql"],
            "urlWhitelist": {
                "allowedUrls": [],
            },
        }
        testlib.post_fail(self.cluster, cred_url(cred_id),
                          400, json=body)

        # Empty disallowedUrls inside urlWhitelist
        body = aws_body()
        body["guardrails"] = {
            "allowedServices": ["n1ql"],
            "urlWhitelist": {
                "disallowedUrls": [],
            },
        }
        testlib.post_fail(self.cluster, cred_url(cred_id),
                          400, json=body)

    def guardrails_url_whitelist_validation_test(self):
        """Validate the urlWhitelist guardrail sub-object.

        Exercises:
          - Invalid URLs in allowedUrls / disallowedUrls are rejected (400).
          - Non-http(s) scheme URLs are rejected.
          - Non-boolean allAccess is rejected.
          - Unknown fields inside urlWhitelist are rejected.
          - A valid urlWhitelist with only allowedUrls (partial) succeeds.
          - A valid urlWhitelist with allAccess=true and no URL lists succeeds.
          - urlWhitelist with only allAccess=false is stored (not omitted).
        """
        cred_id = "test/guardrails/url_whitelist"

        def _try_create(guardrails, expect_fail=False):
            body = aws_body()
            body["guardrails"] = guardrails
            if expect_fail:
                testlib.post_fail(self.cluster, cred_url(cred_id), 400,
                                  json=body)
            else:
                testlib.post_succ(self.cluster, cred_url(cred_id),
                                  json=body, expected_code=201)
                testlib.ensure_deleted(self.cluster, cred_url(cred_id))

        try:
            # --- Invalid URL in allowedUrls ---
            _try_create({
                "urlWhitelist": {
                    "allowedUrls": ["not-a-url"],
                },
            }, expect_fail=True)

            # --- Invalid URL in disallowedUrls ---
            _try_create({
                "urlWhitelist": {
                    "disallowedUrls": ["also not valid"],
                },
            }, expect_fail=True)

            # --- Non-http(s) scheme rejected ---
            _try_create({
                "urlWhitelist": {
                    "allowedUrls": ["ftp://files.example.com/data"],
                },
            }, expect_fail=True)

            # --- Non-boolean allAccess rejected ---
            _try_create({
                "urlWhitelist": {
                    "allAccess": "yes",
                },
            }, expect_fail=True)

            # --- Unknown field inside urlWhitelist rejected ---
            _try_create({
                "urlWhitelist": {
                    "bogusField": True,
                },
            }, expect_fail=True)

            # --- Valid: only allowedUrls (partial urlWhitelist) ---
            _try_create({
                "urlWhitelist": {
                    "allowedUrls": ["https://api.stripe.com/v1"],
                },
            }, expect_fail=False)

            # --- Valid: allAccess=true, no URL lists ---
            body = aws_body()
            body["guardrails"] = {
                "urlWhitelist": {
                    "allAccess": True,
                },
            }
            testlib.post_succ(self.cluster, cred_url(cred_id),
                              json=body, expected_code=201)
            r = testlib.get_succ(self.cluster, cred_url(cred_id))
            gr = r.json()["meta"]["guardrails"]
            assert "urlWhitelist" in gr, \
                f"urlWhitelist should be present: {gr}"
            wl = gr["urlWhitelist"]
            testlib.assert_eq(wl["allAccess"], True,
                              "allAccess=true stored correctly")
            # No allowedUrls / disallowedUrls since they weren't set.
            assert "allowedUrls" not in wl, \
                f"allowedUrls should be absent: {wl}"
            assert "disallowedUrls" not in wl, \
                f"disallowedUrls should be absent: {wl}"
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

            # --- Valid: allAccess=false is stored (not omitted as empty) ---
            body = aws_body()
            body["guardrails"] = {
                "urlWhitelist": {
                    "allAccess": False,
                    "allowedUrls": ["http://internal.corp.example.com/api"],
                },
            }
            testlib.post_succ(self.cluster, cred_url(cred_id),
                              json=body, expected_code=201)
            r = testlib.get_succ(self.cluster, cred_url(cred_id))
            gr = r.json()["meta"]["guardrails"]
            wl = gr["urlWhitelist"]
            testlib.assert_eq(wl["allAccess"], False,
                              "allAccess=false stored correctly")
            testlib.assert_eq(wl["allowedUrls"],
                              ["http://internal.corp.example.com/api"],
                              "allowedUrls with http scheme")

        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def backup_service_consume_test(self):
        """Simulate the continuous backup service consuming a credential.

        The continuous backup service authenticates as @cbcontbk (with the
        special internal password) and passes itself as the on-behalf-of
        user.  @cbcontbk shares roles with @backup via canonical identity
        mapping, so it inherits the credential_consumer role granted to
        @backup in setup().

        The service guardrail is enforced based on the authenticated
        identity (@cbcontbk -> backup service).
        """
        cred_id = "test/consume/backup_e2e"
        secret_val = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        body = aws_body(secret=secret_val)

        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=body, expected_code=201)
        try:
            # Use @cbcontbk instead of @backup to verify canonical identity
            # mapping works - @cbcontbk should inherit @backup's roles.
            cbcontbk_auth = ("@cbcontbk", self.special_password)
            r = cbauth_get(self.node, cred_id, auth=cbcontbk_auth,
                           on_behalf_user="@cbcontbk",
                           on_behalf_domain="admin")
            testlib.assert_http_code(200, r)
            j = r.json()
            testlib.assert_eq(j["id"], cred_id, "id in cbcontbk response")
            testlib.assert_eq(j["type"], "aws", "type in cbcontbk response")
            testlib.assert_eq(j["fields"]["secretAccessKey"], secret_val,
                              "plaintext secret in cbcontbk response")
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def guardrails_n1ql_with_consumer_user_test(self):
        """Full flow test: end-user with credential_consumer role consumes
        via N1QL CURL.

        The service (cbq-engine) authenticates as @cbq-engine for the route
        guard, the RBAC consume check is against the end-user, and the
        guardrail check verifies the calling service is in allowedServices.
        """
        cred_id = "test/guardrails/n1ql_consumer"
        body = aws_body()
        body["guardrails"] = {"allowedServices": ["n1ql"]}
        secret_val = body["fields"]["secretAccessKey"]

        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=body, expected_code=201)
        try:
            # Create a local user with credential_consumer role for this
            # specific credential.
            create_consumer_user(self.cluster, TEST_CONSUMER_USER,
                                 TEST_CONSUMER_PASSWORD, cred_id)

            # The service authenticates as @cbq-engine, but the on-behalf-of
            # user is the local user with credential_consumer role.
            n1ql_auth = ("@cbq-engine", self.special_password)

            # @cbq-engine -> service=n1ql -> allowed by guardrail
            r = cbauth_get(self.node, cred_id, auth=n1ql_auth,
                           on_behalf_user=TEST_CONSUMER_USER,
                           on_behalf_domain="local")
            testlib.assert_http_code(200, r)
            testlib.assert_eq(r.json()["fields"]["secretAccessKey"],
                              secret_val,
                              "plaintext secret for consumer user")

            # @backup -> service=backup -> denied by guardrail for end-user
            backup_auth = ("@backup", self.special_password)
            r = cbauth_get(self.node, cred_id, auth=backup_auth,
                           on_behalf_user=TEST_CONSUMER_USER,
                           on_behalf_domain="local")
            testlib.assert_http_code(403, r)
            code, reason = get_cbauth_error(r.json())
            assert code == "SERVICE_GUARDRAIL_BLOCKED", \
                f"Expected SERVICE_GUARDRAIL_BLOCKED, got: {r.json()}"
        finally:
            delete_consumer_user(self.cluster, TEST_CONSUMER_USER)
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def guardrail_service_user_matrix_test(self):
        """Service-vs-end-user enforcement of allowedServices guardrails.

        Service users (admin domain) bypass the allowedServices guardrail
        because they already require explicit credential_consumer permission.
        End-users (local domain) — even local admin users — are subject to
        the guardrail and must call via a service listed in allowedServices.
        Without an allowedServices guardrail, end-users are denied entirely.
        """
        # Each row creates the credential with the given guardrails (or
        # without them), optionally creates a local on-behalf-of user, then
        # asserts the cbauth response.
        ADMIN_USER = "test_full_admin"
        ADMIN_PW = "password123!"

        # Per-credential matrix: each entry is a (cred_id, guardrails,
        # rows) triple, where rows are
        # (case_name, auth_user, on_behalf_user, on_behalf_domain,
        #  setup_local_user, expected_status, expected_error_code).
        matrix = [
            # Service users bypass even a restrictive allowedServices
            # guardrail.
            ("test/guardrails/backup_only",
             {"allowedServices": ["backup"]},
             [
                 ("backup_admin",  "@backup",     "@backup",
                  "admin", None, 200, None),
                 ("cbcontbk_admin", "@cbcontbk",  "@cbcontbk",
                  "admin", None, 200, None),
                 ("index_admin",   "@index",     "@index",
                  "admin", None, 200, None),
             ]),
            # End-user with allowedServices=[n1ql]: only n1ql allowed.
            ("test/guardrails/n1ql_only",
             {"allowedServices": ["n1ql"]},
             [
                 ("end_user_n1ql",   "@cbq-engine", TEST_CONSUMER_USER,
                  "local", "consumer", 200, None),
                 ("end_user_backup", "@backup",     TEST_CONSUMER_USER,
                  "local", "consumer", 403, "SERVICE_GUARDRAIL_BLOCKED"),
                 ("end_user_index",  "@index",      TEST_CONSUMER_USER,
                  "local", "consumer", 403, "SERVICE_GUARDRAIL_BLOCKED"),
             ]),
            # No guardrail: end-users denied; service users still allowed.
            ("test/guardrails/no_services",
             None,
             [
                 ("no_gr_end_user_index", "@index",      TEST_CONSUMER_USER,
                  "local", "consumer", 403, "SERVICE_GUARDRAIL_BLOCKED"),
                 ("no_gr_end_user_n1ql",  "@cbq-engine", TEST_CONSUMER_USER,
                  "local", "consumer", 403, "SERVICE_GUARDRAIL_BLOCKED"),
                 ("no_gr_svc_index",      "@index",      "@index",
                  "admin", None, 200, None),
                 ("no_gr_svc_n1ql",       "@cbq-engine", "@cbq-engine",
                  "admin", None, 200, None),
             ]),
            # A local user with admin role does NOT bypass guardrails.
            ("test/guardrails/full_admin",
             {"allowedServices": ["n1ql"]},
             [
                 ("full_admin_backup", "@backup",     ADMIN_USER,
                  "local", "admin", 403, "SERVICE_GUARDRAIL_BLOCKED"),
                 ("full_admin_n1ql",   "@cbq-engine", ADMIN_USER,
                  "local", "admin", 200, None),
             ]),
        ]

        for cred_id, guardrails, rows in matrix:
            body = aws_body()
            if guardrails is not None:
                body["guardrails"] = guardrails
            secret_val = body["fields"]["secretAccessKey"]
            testlib.post_succ(self.cluster, cred_url(cred_id),
                              json=body, expected_code=201)
            try:
                local_user_kinds = {row[4] for row in rows
                                    if row[4] is not None}
                if "consumer" in local_user_kinds:
                    create_consumer_user(self.cluster, TEST_CONSUMER_USER,
                                         TEST_CONSUMER_PASSWORD, cred_id)
                if "admin" in local_user_kinds:
                    testlib.put_succ(
                        self.cluster,
                        f"/settings/rbac/users/local/{ADMIN_USER}",
                        data={
                            "roles": (f"admin,"
                                      f"credential_consumer[{cred_id}]"),
                            "password": ADMIN_PW
                        })
                try:
                    for (case, auth_user, ob_user, ob_domain,
                         _kind, expected_status,
                         expected_error) in rows:
                        auth = (auth_user, self.special_password)
                        r = cbauth_get(self.node, cred_id, auth=auth,
                                       on_behalf_user=ob_user,
                                       on_behalf_domain=ob_domain)
                        testlib.assert_http_code(expected_status, r)
                        if expected_status == 200:
                            j = r.json()
                            testlib.assert_eq(j["type"], "aws",
                                              f"type for {case}")
                            # Only end-user (local domain) cases verify the
                            # plaintext secret; service-user cases verify
                            # type only.
                            if ob_domain == "local":
                                testlib.assert_eq(
                                    j["fields"]["secretAccessKey"],
                                    secret_val,
                                    f"plaintext secret for {case}")
                        else:
                            code, _ = get_cbauth_error(r.json())
                            assert code == expected_error, (
                                f"Expected {expected_error} for {case}, "
                                f"got: {r.json()}")
                finally:
                    if "consumer" in local_user_kinds:
                        delete_consumer_user(self.cluster,
                                             TEST_CONSUMER_USER)
                    if "admin" in local_user_kinds:
                        testlib.delete(
                            self.cluster,
                            f"/settings/rbac/users/local/{ADMIN_USER}")
            finally:
                testlib.ensure_deleted(self.cluster, cred_url(cred_id))


# ---------------------------------------------------------------------------
# 3. RBAC
# ---------------------------------------------------------------------------

class CredentialRbacTests(testlib.BaseTestSet):
    """RBAC tests for credential_consumer role grants and the credentials
    permission vertex."""

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise",
                                           encryption=True)

    def setup(self):
        ensure_config_encryption_enabled(self.cluster)
        self.node = self.cluster.connected_nodes[0]
        self.special_password = get_special_password(self.node)
        for svc in SERVICE_CONSUMER_USERS:
            grant_service_consumer_role(self.cluster, svc)

    def teardown(self):
        for svc in SERVICE_CONSUMER_USERS:
            delete_service_consumer_role(self.cluster, svc)

    def test_teardown(self):
        cleanup_ids = ["test/consume/rbac_exact",
                       "test/consume/rbac_prefix",
                       "other/consume/rbac_prefix",
                       "test/consume/expired",
                       "test/consume/backup_e2e"]
        for cred_id in cleanup_ids:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))
        delete_consumer_user(self.cluster, TEST_CONSUMER_USER)

    def credential_consumer_pattern_matrix_test(self):
        """A credential_consumer grant authorizes consumption of credentials
        matching its parameter (exact id or prefix wildcard) and denies
        consumption of credentials outside that pattern.

        Each row sets a different grant pattern and verifies that an allowed
        cred id can be consumed and a denied id cannot.  Both matching styles
        — exact id and prefix wildcard — are exercised.

        Both source tests use @cbq-engine + allowedServices=["n1ql"] to
        isolate RBAC permission checks from guardrail checks.
        """
        # rows: (case_name, grant_pattern, allowed_id, denied_id)
        rows = [
            ("exact",  "test/consume/rbac_exact",
             "test/consume/rbac_exact", "other/consume/rbac_prefix"),
            ("prefix", "test/*",
             "test/consume/rbac_prefix", "other/consume/rbac_prefix"),
        ]

        for case, grant_pattern, allowed_id, denied_id in rows:
            allowed_body = aws_body()
            allowed_body["guardrails"] = {"allowedServices": ["n1ql"]}
            secret_val = allowed_body["fields"]["secretAccessKey"]

            denied_body = aws_body()
            denied_body["guardrails"] = {"allowedServices": ["n1ql"]}

            testlib.post_succ(self.cluster, cred_url(allowed_id),
                              json=allowed_body, expected_code=201)
            testlib.post_succ(self.cluster, cred_url(denied_id),
                              json=denied_body, expected_code=201)
            try:
                create_consumer_user(self.cluster, TEST_CONSUMER_USER,
                                     TEST_CONSUMER_PASSWORD, grant_pattern)

                n1ql_auth = ("@cbq-engine", self.special_password)
                r = cbauth_get(self.node, allowed_id, auth=n1ql_auth,
                               on_behalf_user=TEST_CONSUMER_USER,
                               on_behalf_domain="local")
                testlib.assert_http_code(200, r)
                testlib.assert_eq(r.json()["fields"]["secretAccessKey"],
                                  secret_val,
                                  f"plaintext secret for {case} consumer")

                r = cbauth_get(self.node, denied_id, auth=n1ql_auth,
                               on_behalf_user=TEST_CONSUMER_USER,
                               on_behalf_domain="local")
                testlib.assert_http_code(403, r)
                code, reason = get_cbauth_error(r.json())
                assert code == "INSUFFICIENT_PERMISSIONS", \
                    f"Expected INSUFFICIENT_PERMISSIONS, got: {r.json()}"
            finally:
                delete_consumer_user(self.cluster, TEST_CONSUMER_USER)
                testlib.ensure_deleted(self.cluster, cred_url(allowed_id))
                testlib.ensure_deleted(self.cluster, cred_url(denied_id))

    def expired_credential_test(self):
        """Creating a credential with an expiresAt timestamp in the
        past must be rejected at creation time with 400."""
        cred_id = "test/consume/expired"
        body = aws_body()
        # Set expiresAt to a time in the past (1 second after epoch)
        body["expiresAt"] = 1000

        r = testlib.post_fail(self.cluster, cred_url(cred_id),
                              400, json=body)
        errors = r.json().get("errors", {})
        assert "expiresAt" in errors, \
            f"Expected expiresAt error, got: {r.json()}"

    def credential_consumer_role_id_existence_test(self):
        """Granting `credential_consumer[<id>]' or `[<prefix>/*]' is
        rejected when no matching credential exists.  Wildcard `[*]'
        and `any' are always accepted regardless of the index.

        Guards against typos that would otherwise silently inherit any
        future credential created under the bad id/prefix.
        """
        cred_id = "test/consume/rbac_exact"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            user_url = (
                f'/settings/rbac/users/local/{TEST_CONSUMER_USER}')

            def assert_rejected(role):
                payload = build_payload(roles=role,
                                        password=TEST_CONSUMER_PASSWORD)
                r = testlib.put_fail(
                    self.cluster, user_url, 400, data=payload)
                err = r.json().get("errors", {}).get("roles", "")
                assert "undefined" in err.lower() \
                    or "unknown" in err.lower() \
                    or "malformed" in err.lower(), \
                    f"expected role-validation error, got: {r.json()}"

            def assert_accepted(role):
                try:
                    put_user(self.cluster, 'local', TEST_CONSUMER_USER,
                             password=TEST_CONSUMER_PASSWORD, roles=role)
                finally:
                    delete_consumer_user(self.cluster, TEST_CONSUMER_USER)

            # Rejected: id that does not exist
            assert_rejected("credential_consumer[does/not/exist]")
            # Rejected: prefix with no matches
            assert_rejected("credential_consumer[no/such/prefix/*]")
            # Accepted: existing id
            assert_accepted(f"credential_consumer[{cred_id}]")
            # Accepted: prefix that matches the existing id
            assert_accepted("credential_consumer[test/*]")
            # Accepted: bare wildcard, no existence check
            assert_accepted("credential_consumer[*]")
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def credential_delete_prunes_invalid_roles_test(self):
        """Mirrors the bucket-delete behaviour: when a credential is
        deleted, any role parameterised over that id (and not still
        satisfied by another id under a prefix) must be stripped from
        users automatically.
        """
        exact_id = "test/cleanup/exact"
        prefix_id = "test/cleanup/prefix_only"
        prefix_pattern = "test/cleanup/*"
        wildcard_pattern = "*"

        exact_user = "cred_cleanup_exact"
        prefix_user = "cred_cleanup_prefix"
        wildcard_user = "cred_cleanup_wildcard"

        def get_roles(username):
            r = testlib.get_succ(
                self.cluster,
                f'/settings/rbac/users/local/{username}')
            return [e for e in r.json().get("roles", [])
                    if isinstance(e, dict)
                    and e.get("role") == "credential_consumer"]

        try:
            testlib.post_succ(self.cluster, cred_url(exact_id),
                              json=aws_body(), expected_code=201)
            testlib.post_succ(self.cluster, cred_url(prefix_id),
                              json=aws_body(), expected_code=201)

            create_consumer_user(self.cluster, exact_user,
                                 TEST_CONSUMER_PASSWORD, exact_id)
            create_consumer_user(self.cluster, prefix_user,
                                 TEST_CONSUMER_PASSWORD, prefix_pattern)
            create_consumer_user(self.cluster, wildcard_user,
                                 TEST_CONSUMER_PASSWORD, wildcard_pattern)

            # Sanity: each user starts with the role.
            assert get_roles(exact_user), \
                "exact_user should start with credential_consumer role"
            assert get_roles(prefix_user), \
                "prefix_user should start with credential_consumer role"
            assert get_roles(wildcard_user), \
                "wildcard_user should start with credential_consumer role"

            # Delete the exact-id credential.
            #   - exact_user's role becomes invalid (id no longer exists)
            #     and must be removed.
            #   - prefix_user's role still matches prefix_id under the
            #     same prefix, so it must be retained.
            #   - wildcard_user's [*] is always valid.
            testlib.delete_succ(self.cluster, cred_url(exact_id))

            assert not get_roles(exact_user), (
                f"exact_user must lose credential_consumer[{exact_id}] "
                f"after deletion, got: {get_roles(exact_user)}")
            assert get_roles(prefix_user), (
                "prefix_user must retain credential_consumer"
                f"[{prefix_pattern}] while another id matches the "
                "prefix")
            assert get_roles(wildcard_user), \
                "wildcard_user must retain credential_consumer[*]"

            # Delete the last id under the prefix.
            #   - prefix_user's role no longer matches any id and must
            #     be removed.
            #   - wildcard_user's [*] is always valid.
            testlib.delete_succ(self.cluster, cred_url(prefix_id))

            assert not get_roles(prefix_user), (
                "prefix_user must lose credential_consumer"
                f"[{prefix_pattern}] when no id matches the prefix, "
                f"got: {get_roles(prefix_user)}")
            assert get_roles(wildcard_user), \
                "wildcard_user must retain credential_consumer[*]"
        finally:
            for user in (exact_user, prefix_user, wildcard_user):
                delete_consumer_user(self.cluster, user)
            testlib.ensure_deleted(self.cluster, cred_url(exact_id))
            testlib.ensure_deleted(self.cluster, cred_url(prefix_id))

    def no_consume_role_denied_test(self):
        """When the on-behalf-of user has only ro_admin role (no
        credential_consumer), the consume request must be denied.

        Note: We include allowedServices: ["n1ql"] so that if the RBAC
        check passes, the guardrail would also pass.  This isolates
        testing the RBAC denial.
        """
        cred_id = "test/consume/rbac_exact"
        body = aws_body()
        body["guardrails"] = {"allowedServices": ["n1ql"]}
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=body, expected_code=201)
        try:
            # Create user with ro_admin -- no consume permission
            put_user(self.cluster, 'local', TEST_CONSUMER_USER,
                     password=TEST_CONSUMER_PASSWORD, roles='ro_admin')

            # Service authenticates as @cbq-engine (n1ql) for route guard,
            # but the on-behalf-of user lacks consume permission.
            n1ql_auth = ("@cbq-engine", self.special_password)
            r = cbauth_get(self.node, cred_id, auth=n1ql_auth,
                           on_behalf_user=TEST_CONSUMER_USER,
                           on_behalf_domain="local")
            testlib.assert_http_code(403, r)
            code, reason = get_cbauth_error(r.json())
            assert code == "INSUFFICIENT_PERMISSIONS", \
                f"Expected INSUFFICIENT_PERMISSIONS, got: {r.json()}"
        finally:
            delete_consumer_user(self.cluster, TEST_CONSUMER_USER)
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def check_permissions_credentials_vertex_test(self):
        """POST /pools/default/checkPermissions accepts permission strings
        with a `credentials[<id>]' vertex.

        Exercises the input path: parse_vertex_params/params_length must
        recognise `credentials' as a single-param vertex.  Without that,
        the request would 400 with "Malformed permissions".
        """
        cred_id = "test/consume/rbac_exact"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            create_consumer_user(self.cluster, TEST_CONSUMER_USER,
                                 TEST_CONSUMER_PASSWORD, cred_id)
            consumer_auth = (TEST_CONSUMER_USER, TEST_CONSUMER_PASSWORD)

            perm_exact = f"cluster.credentials[{cred_id}]!consume"
            perm_other = "cluster.credentials[other/missing]!consume"
            perm_any   = "cluster.credentials[.]!consume"
            body = ",".join([perm_exact, perm_other, perm_any])

            r = testlib.post_succ(
                self.cluster, "/pools/default/checkPermissions",
                data=body, auth=consumer_auth)
            result = r.json()
            assert result.get(perm_exact) is True, \
                f"expected consume on {cred_id} to be allowed: {result}"
            assert result.get(perm_other) is False, \
                f"expected consume on other id to be denied: {result}"
            assert perm_any in result, \
                f"any-form perm missing from response: {result}"
        finally:
            delete_consumer_user(self.cluster, TEST_CONSUMER_USER)
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def get_service_roles_returns_role_objects_test(self):
        """GET /settings/rbac/services/<svc>/roles returns each role as a
        JSON object (not a list of [key,val] pairs).

        Setup grants `credential_consumer[*]' to `backup'.
        """
        r = testlib.get_succ(
            self.cluster, '/settings/rbac/services/backup/roles')
        body = r.json()
        roles = body.get("roles")
        assert isinstance(roles, list) and roles, \
            f"expected non-empty roles list, got: {body}"
        for entry in roles:
            assert isinstance(entry, dict), \
                f"each role must be a JSON object, got: {entry!r}"
        assert any(e.get("role") == "credential_consumer"
                   and e.get("credential_id") == "*"
                   for e in roles), \
            f"expected credential_consumer[*] in service roles: {roles}"

    def get_roles_by_credential_permission_existing_id_test(self):
        """GET /settings/rbac/roles?permission=cluster.credentials[<id>]!consume
        returns both the concrete `credential_consumer[<id>]' grant and the
        `credential_consumer[*]' wildcard grant when <id> exists.
        """
        cred_id = "test/consume/rbac_exact"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            perm = f"cluster.credentials[{cred_id}]!consume"
            r = testlib.get_succ(
                self.cluster, '/settings/rbac/roles',
                params={"permission": perm})
            roles = r.json()
            assert isinstance(roles, list), \
                f"expected list of role objects, got: {roles!r}"
            consumer = [e for e in roles
                        if isinstance(e, dict)
                        and e.get("role") == "credential_consumer"]
            ids = sorted(e.get("credential_id") for e in consumer)
            assert ids == sorted([cred_id, "*"]), (
                "expected credential_consumer rows for both the concrete "
                f"id and the wildcard, got: {consumer}")
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def get_roles_by_credential_permission_unknown_id_test(self):
        """GET /settings/rbac/roles with
        permission=cluster.credentials[<bad>]!consume returns only the
        `credential_consumer[*]' wildcard row; no row is emitted for the
        unknown id.
        """
        perm = "cluster.credentials[no/such/id]!consume"
        r = testlib.get_succ(
            self.cluster, '/settings/rbac/roles',
            params={"permission": perm})
        roles = r.json()
        assert isinstance(roles, list), \
            f"expected list of role objects, got: {roles!r}"
        consumer = [e for e in roles
                    if isinstance(e, dict)
                    and e.get("role") == "credential_consumer"]
        ids = [e.get("credential_id") for e in consumer]
        assert ids == ["*"], (
            "unknown credential id must not produce a concrete-id row; "
            f"expected only the wildcard, got: {consumer}")

    def get_roles_by_credential_permission_any_wildcard_test(self):
        """GET /settings/rbac/roles?permission=cluster.credentials[.]!consume
        returns the `credential_consumer[*]' wildcard row.

        The `[.]' form parses to the `any' wildcard and must not require
        the credential index to contain any particular id.
        """
        perm = "cluster.credentials[.]!consume"
        r = testlib.get_succ(
            self.cluster, '/settings/rbac/roles',
            params={"permission": perm})
        roles = r.json()
        consumer = [e for e in roles
                    if isinstance(e, dict)
                    and e.get("role") == "credential_consumer"]
        ids = [e.get("credential_id") for e in consumer]
        assert ids == ["*"], (
            "any-wildcard query must yield exactly the wildcard row, "
            f"got: {consumer}")

    def get_users_by_credential_permission_filters_test(self):
        """GET /settings/rbac/users?permission=cluster.credentials[<id>]!consume
        includes a user holding `credential_consumer[<id>]' and excludes
        users whose only consume grant is for an unrelated id.
        """
        cred_id = "test/consume/rbac_exact"
        other_id = "other/consume/rbac_prefix"
        match_user = "cred_filter_match"
        miss_user = "cred_filter_miss"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        testlib.post_succ(self.cluster, cred_url(other_id),
                          json=aws_body(), expected_code=201)
        try:
            create_consumer_user(self.cluster, match_user,
                                 TEST_CONSUMER_PASSWORD, cred_id)
            create_consumer_user(self.cluster, miss_user,
                                 TEST_CONSUMER_PASSWORD, other_id)

            perm = f"cluster.credentials[{cred_id}]!consume"
            r = testlib.get_succ(
                self.cluster, '/settings/rbac/users',
                params={"permission": perm})
            users = r.json()
            ids = {u.get("id") for u in users
                   if isinstance(u, dict)}
            assert match_user in ids, (
                f"user holding credential_consumer[{cred_id}] must be "
                f"returned, got users: {ids}")
            assert miss_user not in ids, (
                f"user holding only credential_consumer[{other_id}] must "
                f"NOT be returned for permission on {cred_id}, got: {ids}")
        finally:
            delete_consumer_user(self.cluster, match_user)
            delete_consumer_user(self.cluster, miss_user)
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))
            testlib.ensure_deleted(self.cluster, cred_url(other_id))

    def reject_service_self_grant_test(self):
        """A service identity cannot grant itself the
        credential_consumer role. PUT /settings/rbac/services/<name>/roles
        requires [admin, security, admin], write, which service_admin
        denies. Prevents a compromised service from privilege-escalating
        via the service-roles endpoint.
        """
        url = self.node.url + '/settings/rbac/services/backup/roles'
        backup_auth = ("@backup", self.special_password)
        r = requests.put(url, auth=backup_auth,
                         data={'roles': 'credential_consumer[*]'},
                         timeout=10)
        testlib.assert_http_code(403, r)

    def service_admin_credential_access_test(self):
        """Service identities (holding the implicit `service_admin' role)
        can read credential metadata (service_admin grants
        [admin, security], read) but cannot create, update, or delete
        credentials (write on the same vertex is denied).
        """
        cred_id = "test/svc/regression"

        # Seed a credential as Administrator so GET/DELETE have a target.
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            for svc_user in ["@backup", "@cbq-engine", "@cbcontbk"]:
                svc_auth = (svc_user, self.special_password)

                # Read lane — allowed.
                r = requests.get(self.node.url + cred_url(cred_id),
                                 auth=svc_auth, timeout=10)
                testlib.assert_http_code(200, r)

                r = requests.get(self.node.url + "/settings/credentials",
                                 auth=svc_auth, timeout=10)
                testlib.assert_http_code(200, r)

                r = requests.get(
                    self.node.url + "/settings/credentialStore",
                    auth=svc_auth, timeout=10)
                testlib.assert_http_code(200, r)

                # Write lane — denied.
                new_id = f"test/svc/{svc_user.lstrip('@')}_create"
                r = requests.post(self.node.url + cred_url(new_id),
                                  auth=svc_auth, json=aws_body(),
                                  timeout=10)
                testlib.assert_http_code(403, r)

                r = requests.put(self.node.url + cred_url(cred_id),
                                 auth=svc_auth, json=aws_body(),
                                 timeout=10)
                testlib.assert_http_code(403, r)

                r = requests.delete(self.node.url + cred_url(cred_id),
                                    auth=svc_auth, timeout=10)
                testlib.assert_http_code(403, r)
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))


# ---------------------------------------------------------------------------
# 4. Encryption interlock
# ---------------------------------------------------------------------------

CONFIG_ENCR_WARNING = (
    "Stored credentials are not protected by "
    "config encryption at rest")
N2N_WARNING = (
    "Stored credentials risk being sent "
    "unencrypted unless node-to-node encryption")


class CredentialEncryptionInterlockTests(testlib.BaseTestSet):
    """Tests for the interlock between credential store contents and the
    config-encryption / n2n-encryption settings, plus the warnings these
    settings produce."""

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise",
                                           encryption=True)

    def setup(self):
        # These tests toggle config encryption, so save and restore the
        # prior config to avoid leaving the shared cluster in an unexpected
        # state.
        try:
            r = testlib.get(self.cluster, ENCR_AT_REST_CONFIG)
            if r.status_code == 200:
                self._prev_encr_at_rest_config = r.json()
            else:
                self._prev_encr_at_rest_config = None
        except Exception:
            self._prev_encr_at_rest_config = None
        ensure_config_encryption_enabled(self.cluster)
        self.node = self.cluster.connected_nodes[0]
        self.special_password = get_special_password(self.node)

    def teardown(self):
        try:
            prev = getattr(self, "_prev_encr_at_rest_config", None)
            if prev is not None:
                testlib.post_succ(self.cluster, ENCR_AT_REST_CONFIG, json=prev)
        except Exception:
            pass

    def test_teardown(self):
        cleanup_ids = ["test/encr/block_disable",
                       "test/n2n/block_disable",
                       "test/warnings/e2e"]
        for cred_id in cleanup_ids:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    # ------------------------------------------------------------------
    # Helpers for warnings tests
    # ------------------------------------------------------------------

    def _get_list_warnings(self):
        r = testlib.get_succ(self.cluster, CREDS_BASE)
        return list_warnings(r.json())

    def _get_settings_warnings(self):
        r = testlib.get_succ(self.cluster, CREDS_STORE)
        return r.json().get("warnings", [])

    def _assert_warnings(self, expected_kinds, msg):
        """Assert that exactly the given warning kinds are present on both
        the list and settings endpoints.

        expected_kinds is a subset of {"config", "n2n"}.
        """
        for endpoint_name, fetch in (
                ("list", self._get_list_warnings),
                ("settings", self._get_settings_warnings)):
            warnings = fetch()
            for kind, substring in (("config", CONFIG_ENCR_WARNING),
                                    ("n2n", N2N_WARNING)):
                matching = [w for w in warnings if substring in w]
                if kind in expected_kinds:
                    assert len(matching) == 1, (
                        f"{msg} ({endpoint_name}): expected warning "
                        f"containing '{substring}' in {warnings}")
                else:
                    assert len(matching) == 0, (
                        f"{msg} ({endpoint_name}): unexpected warning "
                        f"containing '{substring}' in {warnings}")

    def _disable_autofailover_if_enabled(self):
        """Disable autofailover (required to toggle n2n encryption) and
        return (was_enabled, prior_timeout)."""
        r = testlib.get_succ(self.cluster, '/settings/autoFailover').json()
        af_enabled = r['enabled']
        af_timeout = r['timeout']
        if af_enabled:
            testlib.post_succ(self.cluster, "/settings/autoFailover",
                              data={"enabled": "false"})
        return af_enabled, af_timeout

    def _restore_autofailover(self, af_enabled, af_timeout):
        if af_enabled:
            testlib.post_succ(self.cluster, "/settings/autoFailover",
                              data={"enabled": "true",
                                    "timeout": af_timeout})

    # ------------------------------------------------------------------
    # Disable interlock tests
    # ------------------------------------------------------------------

    def disable_config_encryption_blocked_test(self):
        """Disabling config encryption must fail when the credential
        store is non-empty and config_encryption_override is false
        (the default).

        When the override IS set, disabling should succeed even with
        credentials present, because the store no longer depends on
        config encryption.
        """
        cred_id = "test/encr/block_disable"
        body = aws_body()

        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=body, expected_code=201)
        try:
            # --- Default (no override): disable must be rejected ---
            r = testlib.post_fail(
                self.cluster, ENCR_AT_REST_CONFIG, 400,
                json={"encryptionMethod": "disabled",
                      "encryptionKeyId": -1})
            errors = r.json().get("errors", {})
            err_msg = errors.get("_", "")
            assert cred_id in err_msg, \
                f"Expected credential id in error, got: {errors}"
            assert "configEncryptionOverride" in err_msg, \
                "Expected override hint in error, " \
                f"got: {errors}"

            # --- With override enabled: disable must succeed ---
            testlib.put_succ(
                self.cluster, CREDS_STORE,
                json={"configEncryptionOverride": True,
                      "n2nEncryptionOverride": True})
            try:
                testlib.post_succ(
                    self.cluster, ENCR_AT_REST_CONFIG,
                    json={"encryptionMethod": "disabled",
                          "encryptionKeyId": -1})
            finally:
                # Restore: re-enable encryption and remove override
                ensure_config_encryption_enabled(self.cluster)
                testlib.put_succ(
                    self.cluster, CREDS_STORE,
                    json={"configEncryptionOverride": False,
                          "n2nEncryptionOverride": False})
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def disable_config_encryption_allowed_when_empty_test(self):
        """Disabling config encryption must succeed when the credential
        store is empty (no override needed)."""
        # Ensure no credentials exist (test_teardown should handle this,
        # but be explicit).
        r = testlib.get_succ(self.cluster, CREDS_BASE)
        creds = list_credentials(r.json())
        assert creds == [], \
            f"Expected empty credential store, got: {creds}"

        # Disable config encryption -- should succeed.
        testlib.post_succ(
            self.cluster, ENCR_AT_REST_CONFIG,
            json={"encryptionMethod": "disabled",
                  "encryptionKeyId": -1})

        # Restore encryption for subsequent tests.
        ensure_config_encryption_enabled(self.cluster)

    def disable_n2n_encryption_blocked_test(self):
        """Disabling node-to-node encryption must fail when the
        credential store is non-empty and n2n_encryption_override
        is false (the default).

        When the override IS set, disabling should succeed even
        with credentials present.
        """
        cred_id = "test/n2n/block_disable"
        body = aws_body()
        node = self.cluster.connected_nodes[0]

        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=body, expected_code=201)
        try:
            # Need to disable autoFailover before changing
            # network settings.
            r = testlib.get_succ(
                self.cluster,
                '/settings/autoFailover').json()
            af_enabled = r['enabled']
            af_timeout = r['timeout']
            if af_enabled:
                testlib.post_succ(
                    self.cluster,
                    "/settings/autoFailover",
                    data={"enabled": "false"})

            try:
                # --- Default (no override): disable must
                #     be rejected ---
                r = testlib.post_fail(
                    node,
                    "/node/controller/setupNetConfig",
                    400,
                    data={"nodeEncryption": "off"})
                errors = r.json().get("errors", {})
                err_msg = errors.get(
                    "nodeEncryption",
                    errors.get("_", ""))
                assert "n2nEncryptionOverride" in err_msg, \
                    "Expected n2nEncryptionOverride hint " \
                    f"in error, got: {errors}"

                # --- With override: disable must succeed ---
                testlib.put_succ(
                    self.cluster, CREDS_STORE,
                    json={
                        "configEncryptionOverride": True,
                        "n2nEncryptionOverride": True})
                try:
                    self.cluster.toggle_n2n_encryption(
                        enable=False)
                finally:
                    # Restore n2n encryption and overrides
                    self.cluster.toggle_n2n_encryption(
                        enable=True)
                    testlib.put_succ(
                        self.cluster, CREDS_STORE,
                        json={
                            "configEncryptionOverride":
                                False,
                            "n2nEncryptionOverride":
                                False})
            finally:
                if af_enabled:
                    testlib.post_succ(
                        self.cluster,
                        "/settings/autoFailover",
                        data={
                            "enabled": "true",
                            "timeout": af_timeout})
        finally:
            testlib.ensure_deleted(
                self.cluster, cred_url(cred_id))

    def disable_n2n_encryption_allowed_when_empty_test(self):
        """Disabling n2n encryption must succeed when the
        credential store is empty (no override needed)."""
        r = testlib.get_succ(self.cluster, CREDS_BASE)
        creds = list_credentials(r.json())
        assert creds == [], \
            "Expected empty credential store, " \
            f"got: {creds}"

        r = testlib.get_succ(
            self.cluster,
            '/settings/autoFailover').json()
        af_enabled = r['enabled']
        af_timeout = r['timeout']
        if af_enabled:
            testlib.post_succ(
                self.cluster,
                "/settings/autoFailover",
                data={"enabled": "false"})

        try:
            self.cluster.toggle_n2n_encryption(
                enable=False)
        finally:
            self.cluster.toggle_n2n_encryption(
                enable=True)
            if af_enabled:
                testlib.post_succ(
                    self.cluster,
                    "/settings/autoFailover",
                    data={
                        "enabled": "true",
                        "timeout": af_timeout})

    # ------------------------------------------------------------------
    # Warnings tests
    # ------------------------------------------------------------------

    def warnings_empty_store_test(self):
        """No warnings are emitted when the credential store is empty."""
        testlib.assert_eq(
            self._get_list_warnings(), [],
            "No warnings when store is empty (list)")
        testlib.assert_eq(
            self._get_settings_warnings(), [],
            "No warnings when store is empty (settings)")

    def warnings_protections_enabled_test(self):
        """No warnings are emitted when both protections are enabled
        even if credentials exist."""
        cred_id = "test/warnings/e2e"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            self._assert_warnings(
                set(), "Both protections enabled")
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def warnings_config_encryption_disabled_test(self):
        """Disabling config encryption (with override) emits the
        config-encryption warning on both list and settings endpoints,
        and the warning disappears when re-enabled."""
        cred_id = "test/warnings/e2e"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            testlib.put_succ(
                self.cluster, CREDS_STORE,
                json={"configEncryptionOverride": True,
                      "n2nEncryptionOverride": True})
            try:
                testlib.post_succ(
                    self.cluster, ENCR_AT_REST_CONFIG,
                    json={"encryptionMethod": "disabled",
                          "encryptionKeyId": -1})
                try:
                    self._assert_warnings(
                        {"config"},
                        "Config encr disabled with n2n still enabled")
                finally:
                    ensure_config_encryption_enabled(self.cluster)
            finally:
                testlib.put_succ(
                    self.cluster, CREDS_STORE,
                    json={"configEncryptionOverride": False,
                          "n2nEncryptionOverride": False})

            # --- Both re-enabled: no warnings ---
            self._assert_warnings(
                set(), "After re-enable")
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def warnings_n2n_disabled_test(self):
        """Disabling n2n encryption (with override) emits the n2n warning
        on both list and settings endpoints."""
        cred_id = "test/warnings/e2e"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            testlib.put_succ(
                self.cluster, CREDS_STORE,
                json={"configEncryptionOverride": True,
                      "n2nEncryptionOverride": True})
            try:
                af_enabled, af_timeout = \
                    self._disable_autofailover_if_enabled()
                try:
                    self.cluster.toggle_n2n_encryption(enable=False)
                    try:
                        self._assert_warnings(
                            {"n2n"},
                            "N2N disabled with config encr enabled")
                    finally:
                        self.cluster.toggle_n2n_encryption(enable=True)
                finally:
                    self._restore_autofailover(af_enabled, af_timeout)
            finally:
                testlib.put_succ(
                    self.cluster, CREDS_STORE,
                    json={"configEncryptionOverride": False,
                          "n2nEncryptionOverride": False})
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def warnings_both_disabled_test(self):
        """Disabling both protections (with overrides) emits both warnings
        on both list and settings endpoints."""
        cred_id = "test/warnings/e2e"
        testlib.post_succ(self.cluster, cred_url(cred_id),
                          json=aws_body(), expected_code=201)
        try:
            testlib.put_succ(
                self.cluster, CREDS_STORE,
                json={"configEncryptionOverride": True,
                      "n2nEncryptionOverride": True})
            try:
                af_enabled, af_timeout = \
                    self._disable_autofailover_if_enabled()
                try:
                    self.cluster.toggle_n2n_encryption(enable=False)
                    try:
                        testlib.post_succ(
                            self.cluster, ENCR_AT_REST_CONFIG,
                            json={"encryptionMethod": "disabled",
                                  "encryptionKeyId": -1})
                        try:
                            self._assert_warnings(
                                {"config", "n2n"},
                                "Both disabled")
                        finally:
                            ensure_config_encryption_enabled(self.cluster)
                    finally:
                        self.cluster.toggle_n2n_encryption(enable=True)
                finally:
                    self._restore_autofailover(af_enabled, af_timeout)
            finally:
                testlib.put_succ(
                    self.cluster, CREDS_STORE,
                    json={"configEncryptionOverride": False,
                          "n2nEncryptionOverride": False})
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))


# ---------------------------------------------------------------------------
# 5. Field Validation Tests
# ---------------------------------------------------------------------------

class CredentialValidationTests(testlib.BaseTestSet):
    """Tests for field-level validation of credential types.

    These tests verify that the validators for cert_pem, pkey_pem,
    json_object, http_auth_scheme, and couchbase_encryption_type work
    correctly at the REST API level.
    """

    @staticmethod
    def requirements():
        # Run validation tests on Enterprise with node-to-node encryption
        # enabled to match the main credential store testset.
        return testlib.ClusterRequirements(edition="Enterprise",
                                           encryption=True)

    def setup(self):
        # The credential store requires config encryption at rest to be
        # enabled.  A previous testset on the same shared cluster may have
        # explicitly disabled it, so re-enable it here.
        # Save previous encryption-at-rest config so we can restore it in
        # teardown and avoid leaving the shared cluster in a non-default
        # state.
        try:
            r = testlib.get(self.cluster, ENCR_AT_REST_CONFIG)
            if r.status_code == 200:
                self._prev_encr_at_rest_config = r.json()
            else:
                self._prev_encr_at_rest_config = None
        except Exception:
            self._prev_encr_at_rest_config = None
        ensure_config_encryption_enabled(self.cluster)

    def teardown(self):
        # Restore previous encryption-at-rest config if we saved one.
        try:
            prev = getattr(self, "_prev_encr_at_rest_config", None)
            if prev is not None:
                testlib.post_succ(self.cluster, ENCR_AT_REST_CONFIG, json=prev)
        except Exception:
            pass
        pass

    def teardown(self):
        pass

    def test_teardown(self):
        cleanup_ids = [
            "test/validation/cert_valid",
            "test/validation/cert_invalid",
            "test/validation/pkey_valid",
            "test/validation/pkey_invalid",
            "test/validation/json_valid",
            "test/validation/json_invalid",
            "test/validation/http_scheme_valid",
            "test/validation/http_scheme_invalid",
            "test/validation/couchbase_enc_valid",
            "test/validation/couchbase_enc_invalid",
            "test/validation/http_mtls",
        ]
        for cred_id in cleanup_ids:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    # ------------------------------------------------------------------
    # cert_pem validation
    # ------------------------------------------------------------------

    def valid_certificate_test(self):
        """A valid PEM certificate should be accepted."""
        cred_id = "test/validation/cert_valid"
        body = {
            "type": "http",
            "fields": {
                "authScheme": "mtls",
                "certificate": VALID_CERT_PEM,
                "privateKey": VALID_PKEY_PEM,
            }
        }
        try:
            r = testlib.post_succ(self.cluster, cred_url(cred_id),
                                  json=body, expected_code=201)
            # Verify the certificate is stored (non-sensitive, returned as-is)
            fields = r.json()["fields"]
            assert "certificate" in fields, \
                f"certificate field missing: {fields}"
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def invalid_certificate_rejected_test(self):
        """An invalid certificate should be rejected with 400."""
        cred_id = "test/validation/cert_invalid"
        body = {
            "type": "couchbase",
            "fields": {
                "encryptionType": "none",
                "certificate": "not-a-valid-pem-certificate",
            }
        }
        r = testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        assert "certificate" in field_errors, \
            f"Expected certificate error, got: {errors}"

    # ------------------------------------------------------------------
    # pkey_pem validation
    # ------------------------------------------------------------------

    def valid_private_key_test(self):
        """A valid PEM private key should be accepted."""
        cred_id = "test/validation/pkey_valid"
        body = {
            "type": "http",
            "fields": {
                "authScheme": "mtls",
                "certificate": VALID_CERT_PEM,
                "privateKey": VALID_PKEY_PEM,
            }
        }
        try:
            r = testlib.post_succ(self.cluster, cred_url(cred_id),
                                  json=body, expected_code=201)
            fields = r.json()["fields"]
            # privateKey is sensitive, should be masked
            assert fields.get("privateKey") == "********", \
                f"privateKey should be masked: {fields}"
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def invalid_private_key_rejected_test(self):
        """An invalid private key should be rejected with 400."""
        cred_id = "test/validation/pkey_invalid"
        body = {
            "type": "http",
            "fields": {
                "authScheme": "mtls",
                "certificate": VALID_CERT_PEM,
                "privateKey": "not-a-valid-private-key",
            }
        }
        r = testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        assert "privateKey" in field_errors, \
            f"Expected privateKey error, got: {errors}"

    # ------------------------------------------------------------------
    # json_object validation (GCP jsonCredentials)
    # ------------------------------------------------------------------

    def valid_json_credentials_test(self):
        """Valid JSON object for jsonCredentials should be accepted."""
        cred_id = "test/validation/json_valid"
        body = {
            "type": "gcp",
            "fields": {
                "jsonCredentials":
                    '{"type":"service_account",'
                    '"project_id":"test-project"}',
            }
        }
        try:
            r = testlib.post_succ(self.cluster, cred_url(cred_id),
                                  json=body, expected_code=201)
            # jsonCredentials is sensitive, should be masked
            fields = r.json()["fields"]
            assert fields.get("jsonCredentials") == "********", \
                f"jsonCredentials should be masked: {fields}"
        finally:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def invalid_json_rejected_test(self):
        """Invalid JSON for jsonCredentials should be rejected."""
        cred_id = "test/validation/json_invalid"
        body = {
            "type": "gcp",
            "fields": {
                "jsonCredentials": "not valid json {",
            }
        }
        r = testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        assert "jsonCredentials" in field_errors, \
            f"Expected jsonCredentials error, got: {errors}"

    def json_array_rejected_test(self):
        """JSON array (not object) for jsonCredentials should be rejected."""
        cred_id = "test/validation/json_invalid"
        body = {
            "type": "gcp",
            "fields": {
                "jsonCredentials": '["array", "not", "object"]',
            }
        }
        r = testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        assert "jsonCredentials" in field_errors, \
            f"Expected jsonCredentials error for array, got: {errors}"

    # ------------------------------------------------------------------
    # http_auth_scheme validation
    # ------------------------------------------------------------------

    def valid_auth_scheme_test(self):
        """Valid authScheme values (basic, bearer, mtls) should be accepted."""
        for scheme, extra_fields in [
                ("basic", {"username": "user", "password": "pass"}),
                ("bearer", {"token": "tok123"}),
                ("mtls", {"certificate": VALID_CERT_PEM,
                          "privateKey": VALID_PKEY_PEM}),
        ]:
            cred_id = "test/validation/http_scheme_valid"
            body = {
                "type": "http",
                "fields": {"authScheme": scheme, **extra_fields}
            }
            try:
                r = testlib.post_succ(self.cluster, cred_url(cred_id),
                                      json=body, expected_code=201)
                testlib.assert_eq(r.json()["fields"]["authScheme"], scheme,
                                  f"authScheme should be {scheme}")
            finally:
                testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def invalid_auth_scheme_rejected_test(self):
        """Invalid authScheme value should be rejected."""
        cred_id = "test/validation/http_scheme_invalid"
        body = {
            "type": "http",
            "fields": {
                "authScheme": "invalid_scheme",
                "username": "user",
                "password": "pass",
            }
        }
        r = testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        assert "authScheme" in field_errors, \
            f"Expected authScheme error, got: {errors}"

    # ------------------------------------------------------------------
    # couchbase_encryption_type validation
    # ------------------------------------------------------------------

    def valid_encryption_type_test(self):
        """Valid encryptionType values (none, half, full) should be accepted."""
        for enc_type in ["none", "half", "full"]:
            cred_id = "test/validation/couchbase_enc_valid"
            fields = {"encryptionType": enc_type}
            # half/full require additional fields per cross-field validation.
            if enc_type != "none":
                fields["username"] = "admin"
                fields["password"] = "secret"
            if enc_type == "full":
                fields["certificate"] = VALID_CERT_PEM
                fields["privateKey"] = VALID_PKEY_PEM
            body = {"type": "couchbase", "fields": fields}
            try:
                r = testlib.post_succ(self.cluster, cred_url(cred_id),
                                      json=body, expected_code=201)
                testlib.assert_eq(r.json()["fields"]["encryptionType"],
                                  enc_type,
                                  f"encryptionType should be {enc_type}")
            finally:
                testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def invalid_encryption_type_rejected_test(self):
        """Invalid encryptionType value should be rejected."""
        cred_id = "test/validation/couchbase_enc_invalid"
        body = {
            "type": "couchbase",
            "fields": {
                "encryptionType": "invalid_type",
                "username": "admin",
                "password": "secret",
            }
        }
        r = testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        assert "encryptionType" in field_errors, \
            f"Expected encryptionType error, got: {errors}"

    # ------------------------------------------------------------------
    # Cross-field validation: HTTP scheme requires specific fields
    # ------------------------------------------------------------------

    def http_basic_missing_fields_test(self):
        """HTTP basic auth requires username and password."""
        cred_id = "test/validation/http_scheme_invalid"

        body = {
            "type": "http",
            "fields": {
                "authScheme": "basic",
                # Missing username and password
            }
        }

        r = testlib.request('POST', self.cluster, cred_url(cred_id), json=body)
        assert r.status_code == 400, \
            f"Expected 400, got {r.status_code}: {r.text}"
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        err = field_errors.get("_", "")
        assert "username" in err.lower() or "password" in err.lower(), \
            f"Expected missing field error, got: {r.json()}"

    def http_mtls_missing_fields_test(self):
        """HTTP mtls auth requires certificate and privateKey."""
        cred_id = "test/validation/http_mtls"
        body = {
            "type": "http",
            "fields": {
                "authScheme": "mtls",
                # Missing certificate and privateKey
            }
        }
        r = testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        err = field_errors.get("_", "")
        assert "certificate" in err.lower() or "privatekey" in err.lower(), \
            f"Expected missing field error, got: {r.json()}"

    def http_bearer_missing_token_test(self):
        """HTTP bearer auth requires token."""
        cred_id = "test/validation/http_scheme_invalid"
        body = {
            "type": "http",
            "fields": {
                "authScheme": "bearer",
                # Missing token
            }
        }
        r = testlib.post_fail(self.cluster, cred_url(cred_id), 400, json=body)
        errors = r.json().get("errors", {})
        field_errors = errors.get("fields", errors)
        err = field_errors.get("_", "")
        assert "token" in err.lower(), \
            f"Expected missing token error, got: {r.json()}"


# ---------------------------------------------------------------------------
# 6. PATCH (partial metadata update)
# ---------------------------------------------------------------------------

class CredentialPatchTests(testlib.BaseTestSet):
    """PATCH /settings/credentials/:id — partial metadata update.

    PATCH is the metadata-only counterpart to PUT.  It accepts only
    description, expiresAt, and guardrails; type and fields are immutable
    via this endpoint.  Omitted keys are preserved.
    """

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise",
                                           encryption=True)

    def setup(self):
        ensure_config_encryption_enabled(self.cluster)
        self.node = self.cluster.connected_nodes[0]

    def teardown(self):
        pass

    def test_teardown(self):
        for cred_id in ["test/aws/patch", "test/aws/patch2"]:
            testlib.ensure_deleted(self.cluster, cred_url(cred_id))

    def _create(self, cred_id, **meta):
        body = aws_body()
        body.update(meta)
        r = testlib.post_succ(self.cluster, cred_url(cred_id),
                              json=body, expected_code=201)
        return r.json()

    def patch_description_only_test(self):
        """PATCH description leaves type, fields, and other meta untouched."""
        cred_id = "test/aws/patch"
        future = int(time.time() * 1000) + 24 * 60 * 60 * 1000
        created = self._create(
            cred_id, description="initial",
            expiresAt=future,
            guardrails={"allowedServices": ["n1ql"]})

        r = testlib.patch_succ(self.cluster, cred_url(cred_id),
                               json={"description": "updated"})
        j = r.json()
        testlib.assert_eq(j["meta"]["description"], "updated",
                          "description after patch")
        testlib.assert_eq(j["meta"]["expiresAt"], future,
                          "expiresAt preserved")
        testlib.assert_eq(j["meta"]["guardrails"]["allowedServices"],
                          ["n1ql"], "guardrails preserved")
        testlib.assert_eq(j["type"], "aws", "type preserved")
        testlib.assert_eq(j["fields"]["accessKeyId"],
                          created["fields"]["accessKeyId"],
                          "accessKeyId preserved")
        testlib.assert_eq(j["fields"]["secretAccessKey"], "********",
                          "secretAccessKey masked in PATCH response")
        # updatedAt/updatedBy must be stamped
        assert "updatedAt" in j["meta"], \
            f"updatedAt missing after PATCH: {j['meta']}"
        assert "updatedBy" in j["meta"], \
            f"updatedBy missing after PATCH: {j['meta']}"
        testlib.assert_eq(j["meta"]["createdAt"], created["meta"]["createdAt"],
                          "createdAt preserved")

    def patch_expires_at_only_test(self):
        """PATCH expiresAt leaves description and guardrails untouched."""
        cred_id = "test/aws/patch"
        old_expiry = int(time.time() * 1000) + 24 * 60 * 60 * 1000
        new_expiry = old_expiry + 24 * 60 * 60 * 1000
        self._create(cred_id, description="keep me", expiresAt=old_expiry)

        r = testlib.patch_succ(self.cluster, cred_url(cred_id),
                               json={"expiresAt": new_expiry})
        j = r.json()
        testlib.assert_eq(j["meta"]["expiresAt"], new_expiry,
                          "expiresAt updated")
        testlib.assert_eq(j["meta"]["description"], "keep me",
                          "description preserved")

    def patch_guardrails_only_test(self):
        """PATCH guardrails replaces the guardrails sub-object as a whole."""
        cred_id = "test/aws/patch"
        self._create(cred_id, description="x",
                     guardrails={"allowedServices": ["n1ql"]})

        r = testlib.patch_succ(
            self.cluster, cred_url(cred_id),
            json={"guardrails": {"allowedServices": ["fts", "index"],
                                 "allowedOperations": ["READ"]}})
        j = r.json()
        testlib.assert_eq(j["meta"]["guardrails"]["allowedServices"],
                          ["fts", "index"], "guardrails replaced")
        testlib.assert_eq(j["meta"]["guardrails"]["allowedOperations"],
                          ["READ"], "allowedOperations set")
        testlib.assert_eq(j["meta"]["description"], "x",
                          "description preserved")

    def patch_empty_body_rejected_test(self):
        """PATCH with no recognised fields returns 400."""
        cred_id = "test/aws/patch"
        self._create(cred_id, description="x")

        r = testlib.patch_fail(self.cluster, cred_url(cred_id),
                               400, json={})
        body = r.json()
        err = body.get("error", "")
        assert "description" in err.lower() and "expiresat" in err.lower(), \
            f"Expected error mentioning required fields, got: {body}"

    def patch_rejects_type_and_fields_test(self):
        """PATCH must not accept type or fields — they are PUT-only."""
        cred_id = "test/aws/patch"
        self._create(cred_id, description="x")

        # type is rejected
        r = testlib.patch_fail(self.cluster, cred_url(cred_id),
                               400, json={"type": "azureShared"})
        assert "type" in str(r.json()).lower(), \
            f"Expected unsupported-key error for type, got: {r.json()}"

        # fields is rejected
        r = testlib.patch_fail(
            self.cluster, cred_url(cred_id),
            400, json={"fields": {"accessKeyId": "NEW"}})
        assert "fields" in str(r.json()).lower(), \
            f"Expected unsupported-key error for fields, got: {r.json()}"

        # Verify nothing actually changed
        r = testlib.get_succ(self.cluster, cred_url(cred_id))
        j = r.json()
        testlib.assert_eq(j["type"], "aws",
                          "type unchanged after rejected PATCH")
        testlib.assert_eq(j["fields"]["accessKeyId"], "AKIAIOSFODNN7EXAMPLE",
                          "accessKeyId unchanged after rejected PATCH")

    def patch_not_found_test(self):
        """PATCH on a non-existent credential returns 404."""
        testlib.patch_fail(self.cluster, cred_url("does/not/exist"),
                           404, json={"description": "x"})

    def patch_expires_at_in_past_rejected_test(self):
        """PATCH must enforce the 5-min-future rule on expiresAt."""
        cred_id = "test/aws/patch"
        self._create(cred_id, description="x")

        past = int(time.time() * 1000) - 60_000
        r = testlib.patch_fail(self.cluster, cred_url(cred_id),
                               400, json={"expiresAt": past})
        assert "future" in str(r.json()).lower(), \
            f"Expected 'future' in error, got: {r.json()}"

    def patch_clear_description_test(self):
        """PATCH description: null removes the description from meta."""
        cred_id = "test/aws/patch"
        future = int(time.time() * 1000) + 24 * 60 * 60 * 1000
        self._create(cred_id, description="to be cleared",
                     expiresAt=future)

        r = testlib.patch_succ(self.cluster, cred_url(cred_id),
                               json={"description": None})
        meta = r.json()["meta"]
        assert "description" not in meta, \
            f"description should be cleared, got: {meta}"
        # Other meta preserved
        testlib.assert_eq(meta["expiresAt"], future,
                          "expiresAt preserved after clearing description")

    def patch_clear_expires_at_test(self):
        """PATCH expiresAt: null removes the expiry."""
        cred_id = "test/aws/patch"
        future = int(time.time() * 1000) + 24 * 60 * 60 * 1000
        self._create(cred_id, description="keep me", expiresAt=future)

        r = testlib.patch_succ(self.cluster, cred_url(cred_id),
                               json={"expiresAt": None})
        meta = r.json()["meta"]
        assert "expiresAt" not in meta, \
            f"expiresAt should be cleared, got: {meta}"
        testlib.assert_eq(meta["description"], "keep me",
                          "description preserved after clearing expiresAt")

    def patch_clear_guardrails_test(self):
        """PATCH guardrails: null removes the guardrails sub-object."""
        cred_id = "test/aws/patch"
        self._create(cred_id, description="x",
                     guardrails={"allowedServices": ["n1ql"]})

        r = testlib.patch_succ(self.cluster, cred_url(cred_id),
                               json={"guardrails": None})
        meta = r.json()["meta"]
        assert "guardrails" not in meta, \
            f"guardrails should be cleared, got: {meta}"
        testlib.assert_eq(meta["description"], "x",
                          "description preserved after clearing guardrails")

    def patch_clear_and_set_in_one_request_test(self):
        """PATCH may clear one field and set another in the same request."""
        cred_id = "test/aws/patch"
        future = int(time.time() * 1000) + 24 * 60 * 60 * 1000
        self._create(cred_id, description="old", expiresAt=future)

        r = testlib.patch_succ(self.cluster, cred_url(cred_id),
                               json={"description": "new",
                                     "expiresAt": None})
        meta = r.json()["meta"]
        testlib.assert_eq(meta["description"], "new",
                          "description set in same request")
        assert "expiresAt" not in meta, \
            f"expiresAt should be cleared in same request, got: {meta}"

    def patch_clear_unset_field_is_noop_test(self):
        """Clearing a field that isn't set should succeed and not error."""
        cred_id = "test/aws/patch"
        self._create(cred_id, description="x")  # no expiresAt set

        r = testlib.patch_succ(self.cluster, cred_url(cred_id),
                               json={"expiresAt": None})
        meta = r.json()["meta"]
        assert "expiresAt" not in meta, \
            f"expiresAt should remain absent, got: {meta}"
        testlib.assert_eq(meta["description"], "x",
                          "description preserved")
