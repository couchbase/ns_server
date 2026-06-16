# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import contextlib
import datetime
import os
import shutil
import tempfile

import requests

import testlib
from testsets.cert_load_tests import generate_and_load_internal_client_cert
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CRLTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition='Enterprise')

    def setup(self):
        pass

    def teardown(self):
        pass

    def client_cert_crl_test(self):
        """Test CRL revocation using a full (base) CRL."""
        self._run_crl_revocation_checks(_setup_full_crl, _update_full_crl)

    def delta_crl_base_and_delta_test(self):
        """Test delta CRL: cert1 revoked in base CRL, cert2 in delta CRL."""
        setup_fn, update_fn = _make_delta_crl_ops_base_and_delta()
        self._run_crl_revocation_checks(setup_fn, update_fn)

    def delta_crl_both_in_delta_test(self):
        """Test delta CRL: both certs revoked only in delta CRL."""
        setup_fn, update_fn = _make_delta_crl_ops_both_in_delta()
        self._run_crl_revocation_checks(setup_fn, update_fn)

    def ootb_internal_client_cert_ignores_crl_test(self):
        """Test that OOTB internal client certs bypass CRL checks.

        The cluster's self-generated internal client cert should still work
        even when CRL "Require" policy is active, because is_ootb_cert/1
        exempts certs signed by the cluster's own generated CA.
        """
        node = self.cluster.connected_nodes[0]
        crl_dir = tempfile.mkdtemp()
        ca_ids = []

        try:
            # Generate a CA and dummy cert just to have a valid CRL
            root_ca_pem, root_ca_key_pem = generate_root_ca()
            dummy_cert_pem, _ = generate_client_cert_cn(
                root_ca_pem, root_ca_key_pem, 'dummy')

            ca_ids = load_multiple_cas(node, [root_ca_pem])

            # Enable client cert auth (enable mode - not mandatory)
            testlib.toggle_client_cert_auth(
                node, enabled=True, mandatory=False,
                prefixes=[{'delimiter': '', 'path': 'subject.cn',
                           'prefix': ''}])

            # Create a CRL that revokes the dummy cert (just to make CRL active)
            crl_filepath = os.path.join(crl_dir, 'crl.pem')
            generate_crl_to_file(crl_filepath, root_ca_pem, root_ca_key_pem,
                                 [dummy_cert_pem])

            # Enable CRL with "Require" policy
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Require',
                                               'nodeToNode': 'Disabled'},
                             poll_interval_ms=5000,
                             directory=crl_dir)

            assert_crl_status(self.cluster, expected_status='active')

            # Read the OOTB internal client cert from disk and connect
            with ootb_internal_client_cert_file(node) as cert_path:
                r = try_client_auth(node, cert_path)
                # Should succeed - OOTB certs bypass CRL
                testlib.assert_eq(r.status_code, 200,
                                  name='OOTB cert auth status')
                user_id = r.json().get('id')
                assert user_id == '@internal', \
                    f'Expected @internal user, got {user_id}'
                print(f"OOTB internal cert auth succeeded: user={user_id}")

        finally:
            testlib.toggle_client_cert_auth(node, enabled=False)
            for ca_id in ca_ids:
                testlib.delete(node, f'/pools/default/trustedCAs/{ca_id}')
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             directory='')
            shutil.rmtree(crl_dir, ignore_errors=True)

    def custom_internal_client_cert_crl_test(self):
        """Test that custom internal client certs are subject to CRL checks.

        A custom (uploaded) internal client cert is NOT signed by the cluster's
        generated CA, so CRL checks apply. First verify it works when not
        revoked, then revoke it and verify the connection is rejected.
        """
        node = self.cluster.connected_nodes[0]
        crl_dir = tempfile.mkdtemp()
        ca_ids = []

        try:
            # Generate our own CA for the custom internal client cert
            root_ca_pem, root_ca_key_pem = generate_root_ca()
            ca_ids = load_multiple_cas(node, [root_ca_pem])

            # Enable client cert auth
            testlib.toggle_client_cert_auth(
                node, enabled=True, mandatory=False,
                prefixes=[{'delimiter': '', 'path': 'subject.cn',
                           'prefix': ''}])

            # Generate a custom internal client cert with the special SAN email
            custom_cert_pem, custom_key_pem = \
                generate_and_load_internal_client_cert(node, root_ca_pem,
                                                       root_ca_key_pem,
                                                       'internal')

            # Create an empty CRL (no revocations yet)
            crl_filepath = os.path.join(crl_dir, 'crl.pem')
            generate_crl_to_file(crl_filepath, root_ca_pem, root_ca_key_pem, [])

            # Enable CRL with "Require" policy
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Require',
                                               'nodeToNode': 'Disabled'},
                             poll_interval_ms=5000,
                             directory=crl_dir)

            assert_crl_status(self.cluster, expected_status='active')

            # Step 1: Verify custom internal cert works when NOT revoked
            with client_cert_file(custom_cert_pem, root_ca_pem,
                                  custom_key_pem) as cert_path:
                r = try_client_auth(node, cert_path)
                testlib.assert_eq(r.status_code, 200,
                                  name='custom internal cert before revocation')
                user_id = r.json().get('id')
                assert user_id == '@internal', \
                    f'Expected @internal user, got {user_id}'
                print(f"Custom internal cert auth succeeded: user={user_id}")

                # Step 2: Revoke the custom cert and verify rejection
                generate_crl_to_file(crl_filepath, root_ca_pem, root_ca_key_pem,
                                     [custom_cert_pem])
                assert_reload_crl(node, expected_status='active')

                # Should now be rejected
                assert_cert_rejected(lambda: try_client_auth(node, cert_path))
                print("Custom internal cert correctly rejected after "
                      "revocation")

        finally:
            testlib.toggle_client_cert_auth(node, enabled=False)
            for ca_id in ca_ids:
                testlib.delete(node, f'/pools/default/trustedCAs/{ca_id}')
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             directory='')
            # Regenerate the default internal client cert
            testlib.post_succ(node, '/controller/regenerateCertificate',
                              params={'forceResetCACertificate': 'false',
                                      'dropUploadedCertificates': 'true'})
            shutil.rmtree(crl_dir, ignore_errors=True)

    def _run_crl_revocation_checks(self, setup_crl, update_crl):
        """Shared test body for CRL revocation tests with policy matrix.

        setup_crl(crl_dir, ca_pem, ca_key, revoked_certs) -> state
            writes initial CRL file(s) revoking the given certs
        update_crl(crl_dir, ca_pem, ca_key, extra_certs, state)
            adds extra_certs to the revoked list and rewrites CRL file(s)

        PKI structure:
          Root CA
            ├── Inter CA 1 → cert1 (revoked), cert2 (not revoked initially)
            ├── Inter CA 2 → cert3 (CRL missing — no CRL file written)
            └── Inter CA 3 → cert4 (revoked), cert5 (not revoked); CRL expires
        """
        node = self.cluster.connected_nodes[0]

        user1 = testlib.random_str(8)
        user2 = testlib.random_str(8)
        user3 = testlib.random_str(8)
        user4 = testlib.random_str(8)
        user5 = testlib.random_str(8)
        password = testlib.random_str(8)

        crl_dir = tempfile.mkdtemp()
        ca_ids = []

        try:
            # ------------------------------------------------------------------
            # Step 1: Generate PKI with 3 intermediate CAs
            # ------------------------------------------------------------------
            root_ca_pem, root_ca_key_pem = generate_root_ca()

            inter_ca1_pem, inter_ca1_key_pem = generate_intermediate_ca(
                root_ca_pem, root_ca_key_pem, cn='Test Intermediate CA 1')
            inter_ca2_pem, inter_ca2_key_pem = generate_intermediate_ca(
                root_ca_pem, root_ca_key_pem, cn='Test Intermediate CA 2')
            inter_ca3_pem, inter_ca3_key_pem = generate_intermediate_ca(
                root_ca_pem, root_ca_key_pem, cn='Test Intermediate CA 3')

            # cert1, cert2 from CA1 (normal CRL)
            client_cert1_pem, client_key1_pem = generate_client_cert_cn(
                inter_ca1_pem, inter_ca1_key_pem, user1)
            client_cert2_pem, client_key2_pem = generate_client_cert_cn(
                inter_ca1_pem, inter_ca1_key_pem, user2)

            # cert3 from CA2 (CRL missing)
            client_cert3_pem, client_key3_pem = generate_client_cert_cn(
                inter_ca2_pem, inter_ca2_key_pem, user3)

            # cert4 (revoked, CRL expired), cert5 from CA3 (CRL expired)
            client_cert4_pem, client_key4_pem = generate_client_cert_cn(
                inter_ca3_pem, inter_ca3_key_pem, user4)
            client_cert5_pem, client_key5_pem = generate_client_cert_cn(
                inter_ca3_pem, inter_ca3_key_pem, user5)

            # ------------------------------------------------------------------
            # Step 2: Create RBAC users
            # ------------------------------------------------------------------
            for user in [user1, user2, user3, user4, user5]:
                testlib.put_succ(
                    self.cluster, f'/settings/rbac/users/local/{user}',
                    data={'roles': 'ro_admin', 'password': password})

            # ------------------------------------------------------------------
            # Step 3: Configure client cert auth
            # ------------------------------------------------------------------
            testlib.toggle_client_cert_auth(
                node, enabled=True, mandatory=False,
                prefixes=[{'delimiter': '', 'path': 'subject.cn',
                           'prefix': ''}])

            # ------------------------------------------------------------------
            # Step 4: Load all CAs as trusted
            # ------------------------------------------------------------------
            ca_ids = load_multiple_cas(node, [root_ca_pem, inter_ca1_pem,
                                              inter_ca2_pem, inter_ca3_pem])

            # ------------------------------------------------------------------
            # Step 5: Verify all 5 client certs can authenticate before CRL
            # ------------------------------------------------------------------
            with (client_cert_file(client_cert1_pem, inter_ca1_pem,
                                   client_key1_pem) as cert1_path,
                  client_cert_file(client_cert2_pem, inter_ca1_pem,
                                   client_key2_pem) as cert2_path,
                  client_cert_file(client_cert3_pem, inter_ca2_pem,
                                   client_key3_pem) as cert3_path,
                  client_cert_file(client_cert4_pem, inter_ca3_pem,
                                   client_key4_pem) as cert4_path,
                  client_cert_file(client_cert5_pem, inter_ca3_pem,
                                   client_key5_pem) as cert5_path):

                for i, (cert_path, user) in enumerate([
                        (cert1_path, user1), (cert2_path, user2),
                        (cert3_path, user3), (cert4_path, user4),
                        (cert5_path, user5)], 1):
                    r = testlib.get_succ(node, '/whoami', https=True,
                                         auth=None, cert=cert_path).json()
                    testlib.assert_eq(r['id'], user,
                                      name=f'user{i} /whoami before CRL')

                # --------------------------------------------------------------
                # Step 6: Generate CRLs (cert1 revoked, CA2 missing, CA3 valid)
                # --------------------------------------------------------------

                # CRL for CA1: revokes cert1 (uses callback for full/delta test)
                crl1_state = setup_crl(crl_dir, inter_ca1_pem,
                                       inter_ca1_key_pem, [client_cert1_pem])

                # No CRL for CA2 (missing CRL case)

                # CRL for CA3: expired, revokes cert3
                crl3_state = setup_crl(crl_dir, inter_ca3_pem,
                                       inter_ca3_key_pem, [client_cert4_pem],
                                       expired=True)

                # --------------------------------------------------------------
                # Step 7: Configure CRL directory (policy set per iteration)
                # --------------------------------------------------------------
                set_crl_settings(self.cluster,
                                 policy_per_scope={'clientAuth': 'Disabled',
                                                   'nodeToNode': 'Disabled'},
                                 poll_interval_ms=5000,
                                 directory=crl_dir)

                # --------------------------------------------------------------
                # Step 8: Test each policy after setup_crl (cert1 revoked)
                # --------------------------------------------------------------
                # Expected results for each policy after setup_crl:
                #   cert1: revoked → Require/Permissive=REJECT, Dis=ALLOW
                #   cert2: valid CRL, not revoked → all ALLOW
                #   cert3: missing CRL → Require=REJECT, others=ALLOW
                #   cert4: expired CRL, revoked → Permissive=ALLOW
                #   cert5: expired CRL, not revoked → Permissive=ALLOW
                setup_expectations = {
                    'Require':    {'cert1': False, 'cert2': True,
                                   'cert3': False, 'cert4': False,
                                   'cert5': False},
                    'Permissive': {'cert1': False, 'cert2': True,
                                   'cert3': True, 'cert4': True, 'cert5': True},
                    'Disabled':   {'cert1': True, 'cert2': True,
                                   'cert3': True, 'cert4': True, 'cert5': True},
                }

                cert_paths = {'cert1': cert1_path, 'cert2': cert2_path,
                              'cert3': cert3_path, 'cert4': cert4_path,
                              'cert5': cert5_path}
                cert_users = {'cert1': user1, 'cert2': user2,
                              'cert3': user3, 'cert4': user4, 'cert5': user5}

                for policy, expectations in setup_expectations.items():
                    print(f"\n=== Testing policy: {policy} (after setup) ===")
                    set_crl_settings(
                        self.cluster,
                        policy_per_scope={'clientAuth': policy,
                                          'nodeToNode': 'Disabled'},
                        directory=crl_dir)
                    reload_crl(node)

                    for cert_name, should_allow in expectations.items():
                        print(f"Testing {cert_name} (should_allow={should_allow})...")
                        cert_path = cert_paths[cert_name]
                        self._check_cert_access(
                            node, cert_path, cert_users[cert_name],
                            should_allow, f'{cert_name}/{policy}/setup')

                # --------------------------------------------------------------
                # Step 9: Update CRL(s) to also revoke cert2, expire CA3 CRL
                # --------------------------------------------------------------
                # Update CRL for CA1 to also revoke cert2 (uses callback)
                update_crl(crl_dir, inter_ca1_pem, inter_ca1_key_pem,
                           [client_cert2_pem], crl1_state)
                # Update CRL for CA3: now expired
                update_crl(crl_dir, inter_ca3_pem, inter_ca3_key_pem,
                           [client_cert4_pem], crl3_state, expired=True)

                # --------------------------------------------------------------
                # Step 10: Test each policy after update_crl
                # (cert1+cert2 revoked, CA3 CRL expired)
                # --------------------------------------------------------------

                # cert2, cert5 are now revoked
                update_expectations = {
                    'Require':    {'cert1': False, 'cert2': False,
                                   'cert3': False, 'cert4': False,
                                   'cert5': False},
                    'Permissive': {'cert1': False, 'cert2': False,
                                   'cert3': True, 'cert4': True, 'cert5': True},
                    'Disabled':   {'cert1': True, 'cert2': True,
                                   'cert3': True, 'cert4': True, 'cert5': True},
                }

                for policy, expectations in update_expectations.items():
                    print(f"\n=== Testing policy: {policy} (after update) ===")
                    set_crl_settings(
                        self.cluster,
                        policy_per_scope={'clientAuth': policy,
                                          'nodeToNode': 'Disabled'},
                        directory=crl_dir)
                    reload_crl(node)

                    for cert_name, should_allow in expectations.items():
                        print(f"Testing {cert_name} (should_allow={should_allow})...")
                        cert_path = cert_paths[cert_name]
                        self._check_cert_access(
                            node, cert_path, cert_users[cert_name],
                            should_allow, f'{cert_name}/{policy}/update')

        finally:
            testlib.toggle_client_cert_auth(node, enabled=False)

            for user in [user1, user2, user3, user4, user5]:
                testlib.ensure_deleted(
                    self.cluster, f'/settings/rbac/users/local/{user}')

            for ca_id in ca_ids:
                testlib.delete(node, f'/pools/default/trustedCAs/{ca_id}')

            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             directory="")

            shutil.rmtree(crl_dir, ignore_errors=True)

    def _check_cert_access(self, node, cert_path, expected_user,
                           should_allow, label):
        """Check if cert access is allowed or rejected as expected."""
        if should_allow:
            r = try_client_auth(node, cert_path)
            testlib.assert_eq(r.status_code, 200,
                              name=f'{label} expected ALLOW')
            testlib.assert_eq(r.json()['id'], expected_user,
                              name=f'{label} user id')
            print(f"  {label}: ALLOW (as expected)")
        else:
            assert_cert_rejected(lambda: try_client_auth(node, cert_path))
            print(f"  {label}: REJECT (as expected)")


# =============================================================================
# Full CRL callbacks
# =============================================================================


def _setup_full_crl(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
    """Write a full CRL revoking the given certs. Returns state for update."""
    filename = f'crl_{testlib.random_str(8)}.pem'
    generate_crl_to_file(os.path.join(crl_dir, filename), ca_pem, ca_key_pem,
                         revoked_certs, expired=expired)
    return {'filename': filename, 'revoked': list(revoked_certs)}


def _update_full_crl(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
                     state, expired=False):
    """Update full CRL adding extra certs to revoked list."""
    state['revoked'].extend(extra_revoked_certs)
    generate_crl_to_file(os.path.join(crl_dir, state['filename']), ca_pem,
                         ca_key_pem, state['revoked'], expired=expired)
    return state


# =============================================================================
# Delta CRL callbacks
# =============================================================================


def _make_delta_crl_ops_base_and_delta():
    """Factory for delta CRL ops: revoked_certs in base, extras via delta.

    Returns (setup_fn, update_fn) where:
    - setup: creates base CRL (revoked_certs) + empty delta CRL
    - update: adds extra_certs to the delta CRL
    """
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        base_filename = f'base_{testlib.random_str(8)}.pem'
        delta_filename = f'delta_{testlib.random_str(8)}.pem'
        delta_uri = f'file://{os.path.join(crl_dir, delta_filename)}'
        # Base CRL revokes the given certs
        base_pem, base_num = generate_crl_with_number(
            ca_pem, ca_key_pem, revoked_certs, expired=expired,
            freshest_crl_uri=delta_uri)
        with open(os.path.join(crl_dir, base_filename), 'w') as f:
            f.write(base_pem)
        delta_pem = generate_delta_crl(ca_pem, ca_key_pem, base_num, [])
        with open(os.path.join(crl_dir, delta_filename), 'w') as f:
            f.write(delta_pem)
        return {'base_filename': base_filename,
                'delta_filename': delta_filename,
                'base_num': base_num,
                'delta_revoked': []}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
               state, expired=False):
        state['delta_revoked'].extend(extra_revoked_certs)
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, state['base_num'], state['delta_revoked'],
            expired=expired)
        with open(os.path.join(crl_dir, state['delta_filename']), 'w') as f:
            f.write(delta_pem)
        return state

    return setup, update


def _make_delta_crl_ops_both_in_delta():
    """Factory for delta CRL ops: all certs revoked only via delta CRL.

    Returns (setup_fn, update_fn) where:
    - setup: creates empty base CRL + delta CRL (revoked_certs)
    - update: updates delta CRL to also revoke extra certs
    """
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        base_filename = f'base_{testlib.random_str(8)}.pem'
        delta_filename = f'delta_{testlib.random_str(8)}.pem'
        delta_uri = f'file://{os.path.join(crl_dir, delta_filename)}'
        # Base CRL is empty (no revocations)
        base_pem, base_num = generate_crl_with_number(
            ca_pem, ca_key_pem, [], freshest_crl_uri=delta_uri, expired=expired)
        with open(os.path.join(crl_dir, base_filename), 'w') as f:
            f.write(base_pem)
        # Delta CRL revokes the given certs
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, base_num, revoked_certs, expired=expired)
        with open(os.path.join(crl_dir, delta_filename), 'w') as f:
            f.write(delta_pem)
        return {'base_filename': base_filename, 'delta_filename': delta_filename,
                'base_num': base_num, 'delta_revoked': list(revoked_certs)}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
               state, expired=False):
        state['delta_revoked'].extend(extra_revoked_certs)
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, state['base_num'], state['delta_revoked'],
            expired=expired)
        with open(os.path.join(crl_dir, state['delta_filename']), 'w') as f:
            f.write(delta_pem)
        return state

    return setup, update


# =============================================================================
# Client auth helper
# =============================================================================


def try_client_auth(node, cert_path):
    """Attempt client cert auth with a fresh TLS session.

    Always creates a new requests.Session() to ensure a fresh TLS handshake,
    which is necessary for CRL checks to be evaluated (TLS session resumption
    would skip the verify_fun callback).
    """
    session = requests.Session()
    return testlib.get(node, '/whoami', https=True, auth=None,
                       cert=cert_path, session=session)


# =============================================================================
# CRL API helpers
# =============================================================================


def set_crl_settings(cluster, policy_per_scope=None, directory=None,
                     poll_interval_ms=None):
    """POST /settings/crl to configure CRL settings."""
    body = {}
    if policy_per_scope is not None:
        body['policyPerScope'] = policy_per_scope
    if directory is not None:
        body['directory'] = directory
    if poll_interval_ms is not None:
        body['dirPollIntervalMs'] = poll_interval_ms
    return testlib.post_succ(cluster, '/settings/crl', json=body).json()


def get_crl_settings(cluster):
    """GET /settings/crl to retrieve current CRL settings."""
    return testlib.get_succ(cluster, '/settings/crl').json()


def get_crl_status(cluster):
    """POST /settings/crl/diagnostics/status to get CRL status from all nodes.

    Returns a dict keyed by node hostname, each containing a dict of
    file paths to per-file status objects of the form:
      {"cacheStatus": "active"|"expired"|..., "entries": [...],
       "lastReload": {"result": ..., "time": ..., "errors": [...]}}
    """
    return testlib.post_succ(cluster, '/settings/crl/diagnostics/status',
                             json={}).json()


def reload_crl(node):
    """POST /node/controller/reloadCrl to force immediate CRL reload.

    Returns a dict of file paths to per-file status objects (same format as
    the status endpoint).
    """
    return testlib.post_succ(node, '/node/controller/reloadCrl').json()


def _assert_crl_files(crl_files, expected_status):
    """Assert that at least one CRL file has the expected current status.

    crl_files is a dict of {file_path: status_obj} as returned by both the
    status and reload endpoints, where status_obj['cacheStatus'] is the state
    of the version currently in use.
    """
    assert len(crl_files) > 0, 'Expected at least one CRL file'
    assert any(obj.get('cacheStatus') == expected_status
               for obj in crl_files.values()), \
        f'Expected a {expected_status} CRL file, got: {crl_files}'


def assert_crl_status(cluster, expected_status='active'):
    """Assert that at least one CRL file has the expected current status.

    Fetches CRL status from all nodes and checks that at least one file
    matches the expected status (default: 'active').
    """
    status = get_crl_status(cluster)
    print(f"CRL status: {status}")
    # Flatten node-level dict into a single file-level dict
    all_files = {}
    for node_status in status.values():
        all_files.update(node_status)
    _assert_crl_files(all_files, expected_status)


def assert_reload_crl(node, expected_status='active'):
    """Reload CRL and assert that at least one file has the expected status.

    Calls the reload API and checks that at least one CRL file in the
    response matches the expected current status (default: 'active').
    """
    result = reload_crl(node)
    print(f"Reload CRL response: {result}")
    _assert_crl_files(result, expected_status)


# =============================================================================
# PKI helpers
# =============================================================================


def generate_root_ca():
    """Return (cert_pem, key_pem) for a self-signed root CA."""
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'Test Root CA'),
    ])
    now = datetime.datetime.utcnow()
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                          crl_sign=True, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          content_commitment=False, encipher_only=False,
                          decipher_only=False), critical=True)
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    print(f"Generated root CA: subject={cert.subject}")
    return _cert_and_key_pem(cert, key)


def generate_intermediate_ca(root_ca_pem, root_ca_key_pem,
                             cn='Test Intermediate CA'):
    """Return (cert_pem, key_pem) for an intermediate CA signed by the root."""
    root_cert = x509.load_pem_x509_certificate(root_ca_pem.encode(),
                                               default_backend())
    root_key = serialization.load_pem_private_key(root_ca_key_pem.encode(),
                                                  password=None,
                                                  backend=default_backend())
    inter_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = datetime.datetime.utcnow()
    ski = x509.SubjectKeyIdentifier.from_public_key(inter_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        root_key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(root_cert.subject)
        .public_key(inter_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                          crl_sign=True, key_encipherment=False,
                          data_encipherment=False, key_agreement=False,
                          content_commitment=False, encipher_only=False,
                          decipher_only=False), critical=True)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .sign(root_key, hashes.SHA256(), default_backend())
    )
    print(f"Generated intermediate CA: subject={cert.subject}")
    return _cert_and_key_pem(cert, inter_key)


def generate_client_cert_cn(ca_cert_pem, ca_key_pem, cn):
    """Return (cert_pem, key_pem) for a client cert with CN=cn."""
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(),
                                             default_backend())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(),
                                                password=None,
                                                backend=default_backend())
    client_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend())

    now = datetime.datetime.utcnow()
    ski = x509.SubjectKeyIdentifier.from_public_key(client_key.public_key())
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        ca_key.public_key())

    # CRL Distribution Point - points to the CA that issues CRLs
    cdp = x509.CRLDistributionPoints([
        x509.DistributionPoint(
            full_name=[x509.DirectoryName(ca_cert.subject)],
            relative_name=None,
            reasons=None,
            crl_issuer=None
        )
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
        .add_extension(ski, critical=False)
        .add_extension(aki, critical=False)
        .add_extension(cdp, critical=False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    print(f"Generated client cert: CN={cn}, serial={cert.serial_number}")
    return _cert_and_key_pem(cert, client_key)


# Module-level CRL number counter for generating unique CRL numbers
_crl_number = 0


def generate_crl_to_file(filepath, *args, **kwargs):
    """Generate a CRL and write it to the given filepath."""
    crl_pem = generate_crl(*args, **kwargs)
    with open(filepath, 'w') as f:
        f.write(crl_pem)


def generate_crl(ca_cert_pem, ca_key_pem, revoked_cert_pems, expired=False):
    """Return a PEM-encoded CRL signed by the given CA.

    If expired=True, generates a CRL with nextUpdate in the past (expired).
    """
    pem, _ = generate_crl_with_number(ca_cert_pem, ca_key_pem,
                                       revoked_cert_pems, expired=expired)
    return pem


def generate_crl_with_number(ca_cert_pem, ca_key_pem, revoked_cert_pems,
                             expired=False, freshest_crl_uri=None):
    """Return (pem, crl_number) for a CRL signed by the given CA.

    revoked_cert_pems is a list of PEM strings whose serial numbers will be
    added to the revocation list.

    If expired=True, generates a CRL with nextUpdate in the past (expired).

    If freshest_crl_uri is provided, a FreshestCRL extension is added
    pointing to the delta CRL location (required when using delta CRLs).
    """
    global _crl_number
    _crl_number += 1
    crl_num = _crl_number

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(),
                                             default_backend())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(),
                                                password=None,
                                                backend=default_backend())
    now = datetime.datetime.now(datetime.timezone.utc)

    # Authority Key Identifier from the CA's public key
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        ca_key.public_key())

    # Issuing Distribution Point - must match the CDP in client certs
    idp = x509.IssuingDistributionPoint(
        full_name=[x509.DirectoryName(ca_cert.subject)],
        relative_name=None,
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=False
    )

    # Set nextUpdate to past (expired) or future (valid) based on flag
    if expired:
        next_update = now - datetime.timedelta(days=1)
    else:
        next_update = now + datetime.timedelta(days=1)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(days=2))
        .next_update(next_update)
        .add_extension(x509.CRLNumber(crl_num), critical=False)
        .add_extension(aki, critical=False)
        .add_extension(idp, critical=True)
    )
    if freshest_crl_uri is not None:
        dp = x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(freshest_crl_uri)],
            relative_name=None,
            reasons=None,
            crl_issuer=None
        )
        builder = builder.add_extension(
            x509.FreshestCRL([dp]), critical=False)
    revoked_serials = []
    for cert_pem in revoked_cert_pems:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(),
                                              default_backend())
        revoked_serials.append(cert.serial_number)
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(cert.serial_number)
            .revocation_date(now)
            .build(default_backend())
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(ca_key, hashes.SHA256(), default_backend())
    _print_crl_info(crl, "base CRL")
    return crl.public_bytes(serialization.Encoding.PEM).decode(), crl_num


def generate_delta_crl(ca_cert_pem, ca_key_pem, base_crl_number,
                       revoked_cert_pems, expired=False):
    """Return a PEM-encoded delta CRL referencing the given base CRL.

    The delta CRL contains revocations added since the base CRL was issued.
    The DeltaCRLIndicator extension marks this as a delta CRL and contains
    the base CRL number.
    """
    global _crl_number
    _crl_number += 1
    crl_num = _crl_number

    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode(),
                                             default_backend())
    ca_key = serialization.load_pem_private_key(ca_key_pem.encode(),
                                                password=None,
                                                backend=default_backend())
    now = datetime.datetime.now(datetime.timezone.utc)

    # Authority Key Identifier from the CA's public key
    aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        ca_key.public_key())

    # Issuing Distribution Point - must match the CDP in client certs
    idp = x509.IssuingDistributionPoint(
        full_name=[x509.DirectoryName(ca_cert.subject)],
        relative_name=None,
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=False
    )

    # DeltaCRLIndicator marks this as a delta CRL and references the base
    delta_indicator = x509.DeltaCRLIndicator(base_crl_number)

    if expired:
        next_update = now - datetime.timedelta(days=1)
    else:
        next_update = now + datetime.timedelta(days=1)

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now - datetime.timedelta(days=2))
        .next_update(next_update)
        .add_extension(x509.CRLNumber(crl_num), critical=False)
        .add_extension(aki, critical=False)
        .add_extension(idp, critical=True)
        .add_extension(delta_indicator, critical=True)
    )
    for cert_pem in revoked_cert_pems:
        cert = x509.load_pem_x509_certificate(cert_pem.encode(),
                                              default_backend())
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(cert.serial_number)
            .revocation_date(now)
            .build(default_backend())
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(ca_key, hashes.SHA256(), default_backend())
    _print_crl_info(crl, f"delta CRL (base={base_crl_number})")
    return crl.public_bytes(serialization.Encoding.PEM).decode()


def _print_crl_info(crl, label):
    """Print decoded CRL info for debugging."""
    revoked_certs = [
        {'serial': r.serial_number, 'revocation_date': r.revocation_date,
         'extensions': [e for e in r.extensions]}
        for r in crl
    ]
    print(f"Generated {label}: issuer={crl.issuer}, "
          f"last_update={crl.last_update}, next_update={crl.next_update}, "
          f"signature_algorithm={crl.signature_algorithm_oid}, "
          f"extensions={[e for e in crl.extensions]}, "
          f"revoked_certs={revoked_certs}")


def _cert_and_key_pem(cert, key):
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
    return cert_pem, key_pem


# =============================================================================
# CA loading helper
# =============================================================================

def load_multiple_cas(node, ca_pems):
    """Write several CA PEM strings to the node's inbox/CA directory and load
    them all in a single loadTrustedCAs call.

    Returns the list of CA IDs that were loaded (for use in teardown).
    """
    ca_dir = os.path.join(node.data_path(), 'inbox', 'CA')
    os.makedirs(ca_dir, exist_ok=True)
    ca_paths = []
    try:
        for i, ca_pem in enumerate(ca_pems):
            ca_path = os.path.join(ca_dir, f'ca_{i}.pem')
            with open(ca_path, 'w') as f:
                f.write(ca_pem)
            ca_paths.append(ca_path)
        r = testlib.post_succ(node, '/node/controller/loadTrustedCAs')
        ca_ids = [c['id'] for c in r.json()]
        print(f"Loaded {len(ca_ids)} CAs: ids={ca_ids}")
        return ca_ids
    finally:
        for p in ca_paths:
            if os.path.exists(p):
                os.remove(p)


# =============================================================================
# Client cert file helper
# =============================================================================

@contextlib.contextmanager
def client_cert_file(cert_pem, chain_pem, key_pem):
    """Context manager that writes cert + chain + key to a temp PEM file.

    The chain cert (intermediate CA) is included so the server can verify the
    full certificate chain without having to look it up separately.
    """
    f = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.pem')
    try:
        f.write(cert_pem)
        f.write('\n')
        f.write(chain_pem)
        f.write('\n')
        f.write(key_pem)
        f.close()
        yield f.name
    finally:
        try:
            f.close()
        except Exception:
            pass
        if os.path.exists(f.name):
            os.unlink(f.name)


# =============================================================================
# CRL rejection assertion
# =============================================================================

# TLS alert strings observed in practice when a certificate is revoked or the
# handshake fails for another cert-related reason.
_REVOKED_ALERT = 'SSLV3_ALERT_CERTIFICATE_REVOKED'
_HANDSHAKE_ALERT = 'SSLV3_ALERT_HANDSHAKE_FAILURE'
_BAD_CERTIFICATE_ALERT = 'SSLV3_ALERT_BAD_CERTIFICATE'


def assert_cert_rejected(fun):
    """Assert that calling fun() results in a TLS-level rejection.

    Polls with short retries to tolerate a brief propagation delay between
    the CRL settings POST and the first enforced check.
    """
    def do():
        try:
            r = fun()
            # Some implementations may do the CRL check at the application
            # layer and return an HTTP error instead of a TLS alert.
            assert r.status_code in (401, 403), \
                f'Expected cert rejection (401/403) but got {r.status_code}'
        except requests.exceptions.SSLError as e:
            err_str = str(e)
            # Transient EOF can appear; treat as "not yet enforced".
            if 'EOF occurred in violation of protocol' in err_str:
                return False
            assert (_REVOKED_ALERT in err_str or
                    _HANDSHAKE_ALERT in err_str or
                    _BAD_CERTIFICATE_ALERT in err_str), \
                f'Unexpected SSLError (expected revocation or handshake ' \
                f'failure): {e}'
        return True

    testlib.poll_for_condition(do, sleep_time=0.5, attempts=20,
                               msg='waiting for CRL revocation to be enforced')


# =============================================================================
# Internal client cert helpers
# =============================================================================


@contextlib.contextmanager
def ootb_internal_client_cert_file(node):
    """Context manager that reads the OOTB internal client cert from disk.

    Reads the cert and key from the node's config/certs directory, extracts
    the passphrase via diag/eval if needed, decrypts the key if encrypted,
    and writes everything to a temp file suitable for requests library.

    Note: requests library doesn't support passphrase-protected keys directly,
    so we must decrypt encrypted keys before writing them to the temp file.
    """
    certs_dir = os.path.join(node.data_path(), 'config', 'certs')
    chain_path = os.path.join(certs_dir, 'client_chain.pem')
    pkey_path = os.path.join(certs_dir, 'client_pkey.pem')

    with open(chain_path, 'r') as f:
        cert_pem = f.read()
    with open(pkey_path, 'r') as f:
        key_pem = f.read()

    # Check if the key is encrypted by trying to load it without passphrase
    try:
        serialization.load_pem_private_key(
            key_pem.encode(), password=None, backend=default_backend())
        # Key is not encrypted, use as-is
        print("OOTB internal client key is not encrypted")
    except (TypeError, ValueError):
        # Key is encrypted, need to extract passphrase and decrypt
        print("OOTB internal client key is encrypted, extracting passphrase")
        r = testlib.diag_eval(
            node, '(ns_secrets:get_pkey_pass(client_cert))().')
        passphrase_str = r.text.strip()
        print(f"Extracted passphrase response: {passphrase_str}")

        if passphrase_str == 'undefined':
            raise ValueError("Key is encrypted but passphrase is undefined")

        # Remove surrounding quotes if present
        passphrase = passphrase_str.strip('"')
        key_pem = _decrypt_pem_key(key_pem, passphrase)

    # Write to temp file
    f = tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.pem')
    try:
        f.write(cert_pem)
        f.write('\n')
        f.write(key_pem)
        f.close()
        yield f.name
    finally:
        try:
            f.close()
        except Exception:
            pass
        if os.path.exists(f.name):
            os.unlink(f.name)


def _decrypt_pem_key(encrypted_key_pem, passphrase):
    """Decrypt a PEM-encoded private key using the passphrase.

    Uses cryptography library to load and re-serialize without encryption.
    This is needed because requests library doesn't support passphrase-protected
    keys directly.
    """
    key = serialization.load_pem_private_key(
        encrypted_key_pem.encode(),
        password=passphrase.encode(),
        backend=default_backend())
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()).decode()
