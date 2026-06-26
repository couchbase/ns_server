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
import http.server
import os
import shutil
import socketserver
import tempfile
import threading

import requests

import testlib
from testsets.cert_load_tests import generate_and_load_node_cert, \
                                     generate_and_load_internal_client_cert
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
        set_allow_expired_crls(self.cluster, True)
        # HTTP server for URL-based CRL tests; started here, stopped in
        # teardown.  Poll the URLs frequently so the auto-poll timer is
        # snappy (the URL revocation tests force a reload for determinism).
        self._url_server = CRLHttpServer()
        self._url_server.start()
        set_crl_settings(self.cluster, url_poll_interval_ms=1000)

    def teardown(self):
        try:
            set_allow_expired_crls(self.cluster, False)
        finally:
            server = getattr(self, '_url_server', None)
            if server is not None:
                server.stop()

    def client_cert_crl_test(self):
        """Test CRL revocation using a full (base) CRL."""
        self._run_crl_revocation_checks(_setup_full_crl, _update_full_crl)

    def client_cert_upload_crl_test(self):
        """Test CRL revocation using the REST file upload API."""
        node = self.cluster.connected_nodes[0]
        setup_fn, update_fn = _make_upload_crl_ops(node)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=False)

    def client_cert_upload_rename_test(self):
        """Upload-based CRL test where update uses a different filename."""
        node = self.cluster.connected_nodes[0]
        setup_fn, update_fn = _make_upload_crl_ops_rename(node)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=False)

    def client_cert_upload_delta_test(self):
        """Delta CRL test: both base and delta uploaded via REST API."""
        node = self.cluster.connected_nodes[0]
        setup_fn, update_fn = _make_upload_delta_crl_ops(node)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=False)

    def client_cert_upload_delta_rename_test(self):
        """Delta CRL test where delta update uses a different filename."""
        node = self.cluster.connected_nodes[0]
        setup_fn, update_fn = _make_upload_delta_crl_ops_rename(node)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=False)

    def client_cert_base_dir_delta_upload_test(self):
        """Base CRL deployed via directory; delta CRL uploaded via API."""
        node = self.cluster.connected_nodes[0]
        setup_fn, update_fn = _make_hybrid_base_dir_delta_upload_ops(node)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=True)

    def client_cert_dir_setup_upload_update_test(self):
        """Initial CRL via directory; update switches to REST API upload."""
        node = self.cluster.connected_nodes[0]
        setup_fn, update_fn = _make_hybrid_dir_setup_upload_update_ops(node)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=True)

    def client_cert_upload_setup_dir_update_test(self):
        """Initial CRL uploaded via API; update writes to directory."""
        node = self.cluster.connected_nodes[0]
        setup_fn, update_fn = _make_hybrid_upload_setup_dir_update_ops(node)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=True)

    def delta_crl_base_and_delta_test(self):
        """Test delta CRL: cert1 revoked in base CRL, cert2 in delta CRL."""
        setup_fn, update_fn = _make_delta_crl_ops_base_and_delta()
        self._run_crl_revocation_checks(setup_fn, update_fn)

    def delta_crl_both_in_delta_test(self):
        """Test delta CRL: both certs revoked only in delta CRL."""
        setup_fn, update_fn = _make_delta_crl_ops_both_in_delta()
        self._run_crl_revocation_checks(setup_fn, update_fn)

    def client_cert_url_crl_test(self):
        """Test CRL revocation using full CRLs served over HTTP URLs."""
        setup_fn, update_fn = self._make_url_crl_ops(self._url_server)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=True)

    def client_cert_url_delta_crl_test(self):
        """Test delta CRL revocation served over HTTP URLs (base + delta)."""
        setup_fn, update_fn = self._make_url_delta_crl_ops(self._url_server)
        self._run_crl_revocation_checks(setup_fn, update_fn,
                                        reload_in_loop=True)

    def ootb_internal_client_cert_crl_test(self):
        """OOTB internal client certs validate via the auto-generated OOTB CRL.

        There is no is_ootb_cert special-case any more: the cluster publishes an
        empty CRL issued by its self-generated (OOTB) CA, so an OOTB cert is
        checked like any other cert and comes out 'good' (its serial is not on
        the revocation list).  This works with NO uploaded / poll-directory
        CRLs at all — purely the generated CRL — which is what memcached needs.
        """
        node = self.cluster.connected_nodes[0]

        try:
            # Enable client cert auth (enable mode - not mandatory)
            testlib.toggle_client_cert_auth(
                node, enabled=True, mandatory=False,
                prefixes=[{'delimiter': '', 'path': 'subject.cn',
                           'prefix': ''}])

            # Enable CRL with "Require" policy and NO directory/uploads: the
            # only CRL available is the auto-generated OOTB CRL.
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Require',
                                               'nodeToNode': 'Disabled'})

            # The auto-generated OOTB CRL must be present and active, and it
            # must be reported with the 'generated' source.
            status = get_crl_status(self.cluster)
            print(f"CRL status: {status}")
            all_files = [f for node_files in status.values()
                         if isinstance(node_files, list)
                         for f in node_files]
            generated = [f for f in all_files
                         if f.get('source') == 'generated']
            assert len(generated) > 0, \
                f'Expected a generated OOTB CRL, got: {all_files}'
            assert any(f.get('cacheStatus') == 'active' for f in generated), \
                f'Expected an active generated OOTB CRL, got: {generated}'

            # Read the OOTB internal client cert from disk and connect.
            with ootb_internal_client_cert_file(node) as cert_path:
                r = try_client_auth(node, cert_path)
                # Should succeed - validated as 'good' against the OOTB CRL.
                testlib.assert_eq(r.status_code, 200,
                                  name='OOTB cert auth status')
                user_id = r.json().get('id')
                assert user_id == '@internal', \
                    f'Expected @internal user, got {user_id}'
                print(f"OOTB internal cert auth succeeded: user={user_id}")

        finally:
            testlib.toggle_client_cert_auth(node, enabled=False)
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'})

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

    def intermediate_cert_crl_test(self):
        """CRL check applied to a revoked intermediate CA certificate.

        When checkIntermediateCerts is enabled, a client cert whose chain
        contains a revoked intermediate CA is rejected even if the leaf
        cert is not explicitly listed in any CRL.
        """
        node = self.cluster.connected_nodes[0]
        ca_ids = []

        try:
            user = testlib.random_str(8)
            password = testlib.random_str(8)

            # PKI: Root CA -> Intermediate CA -> client leaf cert.
            root_ca_pem, root_ca_key_pem = generate_root_ca()
            inter_ca_pem, inter_ca_key_pem = generate_intermediate_ca(
                root_ca_pem, root_ca_key_pem,
                cn='Test Revoked Inter CA')
            client_cert_pem, client_key_pem = generate_client_cert_cn(
                inter_ca_pem, inter_ca_key_pem, user)

            testlib.put_succ(
                self.cluster, f'/settings/rbac/users/local/{user}',
                data={'roles': 'ro_admin', 'password': password})

            testlib.toggle_client_cert_auth(
                node, enabled=True, mandatory=False,
                prefixes=[{'delimiter': '', 'path': 'subject.cn',
                           'prefix': ''}])

            ca_ids = load_multiple_cas(node, [root_ca_pem, inter_ca_pem])

            # Root CA issues a CRL that revokes the intermediate CA cert.
            root_crl = generate_crl(root_ca_pem, root_ca_key_pem,
                                    [inter_ca_pem])
            upload_crl_file(node, 'root_crl.pem', root_crl)

            with client_cert_file(client_cert_pem, inter_ca_pem,
                                  client_key_pem) as cert_path:
                # Step 1: checkIntermediateCerts disabled (default).
                # Permissive policy: leaf cert has no CRL (undetermined
                # status), which permissive mode allows.
                set_crl_settings(
                    self.cluster,
                    policy_per_scope={'clientAuth': 'Permissive',
                                      'nodeToNode': 'Disabled'},
                    check_intermediate_certs=False)
                assert_crl_status(self.cluster, expected_status='active')
                r = try_client_auth(node, cert_path)
                testlib.assert_eq(
                    r.status_code, 200,
                    name='allowed without intermediate cert check')
                print("Connection allowed "
                      "(checkIntermediateCerts=false)")

                # Step 2: enable checkIntermediateCerts.
                # The intermediate CA cert is in the Root CA's CRL,
                # so the connection must be rejected.
                set_crl_settings(
                    self.cluster,
                    policy_per_scope={'clientAuth': 'Permissive',
                                      'nodeToNode': 'Disabled'},
                    check_intermediate_certs=True)
                assert_cert_rejected(
                    lambda: try_client_auth(node, cert_path))
                print("Connection rejected "
                      "(intermediate CA is revoked)")

                # Step 3: disable intermediate cert checking again.
                # the connection is rejected because leaf cert status
                # is undetermined (not listed in CRL)
                set_crl_settings(
                    self.cluster,
                    policy_per_scope={'clientAuth': 'Require',
                                      'nodeToNode': 'Disabled'},
                    check_intermediate_certs=False)
                assert_cert_rejected(
                    lambda: try_client_auth(node, cert_path))
                print("Connection rejected (leaf cert is undetermined)")

                # Step 4: generate a CRL for leaf cert (issued by intermediate
                # CA) and check connection is allowed again.
                int_crl = generate_crl(inter_ca_pem, inter_ca_key_pem, [])
                upload_crl_file(node, 'inter_crl.pem', int_crl)

                r = try_client_auth(node, cert_path)
                testlib.assert_eq(
                    r.status_code, 200,
                    name='allowed after disabling intermediate check')
                print("Connection allowed again "
                      "(checkIntermediateCerts=false)")

        finally:
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             check_intermediate_certs=False,
                             directory="")
            testlib.toggle_client_cert_auth(node, enabled=False)
            testlib.ensure_deleted(
                self.cluster,
                f'/settings/rbac/users/local/{user}')
            for ca_id in ca_ids:
                testlib.delete(
                    node,
                    f'/pools/default/trustedCAs/{ca_id}')
            for f in get_crl_files(node):
                delete_crl_file(node, f['filename'])

    def _run_crl_revocation_checks(self, setup_crl, update_crl,
                                   reload_in_loop=True):
        """Shared test body for CRL revocation tests with policy matrix.

        setup_crl(crl_dir, ca_pem, ca_key, revoked_certs) -> state
            writes initial CRL file(s) revoking the given certs
        update_crl(crl_dir, ca_pem, ca_key, extra_certs, state)
            adds extra_certs to the revoked list and rewrites CRL file(s)

        reload_in_loop: whether reload_crl() is called in each policy loop to
            force an immediate (re)load of CRLs.

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

            # Different certs with the same CN; to make sure the server
            # can find the correct one by AKI/SKI
            fake_inter_ca1_pem1, _ = generate_intermediate_ca(
                root_ca_pem, root_ca_key_pem, cn='Test Intermediate CA 1')
            fake_inter_ca1_pem2, _ = generate_intermediate_ca(
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
            ca_ids = load_multiple_cas(node, [root_ca_pem, fake_inter_ca1_pem1,
                                              inter_ca1_pem, inter_ca2_pem,
                                              inter_ca3_pem,
                                              fake_inter_ca1_pem2])

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
                # Step 7: Configure CRL settings (policy set per iteration)
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
                    if reload_in_loop:
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
                    if reload_in_loop:
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
                             directory="", urls=[])

            # Clean up any files uploaded via the REST API (upload-based
            # and hybrid tests leave files that poll teardown misses).
            for f in get_crl_files(node):
                delete_crl_file(node, f['filename'])

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

    def _add_crl_urls(self, new_urls):
        """Append URLs to /settings/crl, preserving the ones already there.

        set_config replaces crl_urls wholesale (it does not append), so read
        the current list via GET /settings/crl and POST the union.
        """
        current = get_crl_settings(self.cluster).get('urls', [])
        set_crl_settings(self.cluster, urls=current + new_urls)

    def _make_url_crl_ops(self, server):
        """Factory for URL-based full-CRL ops.

        setup: writes a full CRL to the HTTP server under a unique path and
            registers its URL via /settings/crl.
        update: just rewrites the CRL content on the HTTP server (no settings
            POST, no reload -- the shared loop reloads to fetch the change).
        """
        def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
            path = f'/crl_{testlib.random_str(8)}.pem'
            crl_pem = generate_crl(ca_pem, ca_key_pem, revoked_certs,
                                   expired=expired)
            server.set_path_content(path, crl_pem)
            self._add_crl_urls([server.url_for(path)])
            return {'path': path, 'revoked': list(revoked_certs)}

        def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
                   state, expired=False):
            state['revoked'].extend(extra_revoked_certs)
            crl_pem = generate_crl(ca_pem, ca_key_pem, state['revoked'],
                                   expired=expired)
            server.set_path_content(state['path'], crl_pem)
            return state

        return setup, update

    def _make_url_delta_crl_ops(self, server):
        """Factory for URL-based delta-CRL ops (base + delta, 2 URLs per CA).

        setup: revoked_certs go in the base CRL; an (initially empty) delta
            CRL is served from a second URL referenced by the base CRL's
            FreshestCRL extension.  Both URLs are registered via /settings/crl.
        update: rewrites only the delta CRL on the HTTP server.
        """
        def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
            base_path = f'/base_{testlib.random_str(8)}.pem'
            delta_path = f'/delta_{testlib.random_str(8)}.pem'
            delta_uri = server.url_for(delta_path)
            base_pem, base_num = generate_crl_with_number(
                ca_pem, ca_key_pem, revoked_certs, expired=expired,
                freshest_crl_uri=delta_uri)
            server.set_path_content(base_path, base_pem)
            delta_pem = generate_delta_crl(ca_pem, ca_key_pem, base_num, [])
            server.set_path_content(delta_path, delta_pem)
            self._add_crl_urls([server.url_for(base_path), delta_uri])
            return {'delta_path': delta_path, 'base_num': base_num,
                    'delta_revoked': []}

        def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
                   state, expired=False):
            state['delta_revoked'].extend(extra_revoked_certs)
            delta_pem = generate_delta_crl(
                ca_pem, ca_key_pem, state['base_num'], state['delta_revoked'],
                expired=expired)
            server.set_path_content(state['delta_path'], delta_pem)
            return state

        return setup, update


# =============================================================================
# Upload API helpers
# =============================================================================


def upload_crl_file(node, filename, crl_pem):
    """Upload a CRL file via POST /settings/crl/files (multipart/form-data).

    Returns the requests.Response (body: updated list of uploaded files).
    """
    if isinstance(crl_pem, str):
        crl_pem = crl_pem.encode()
    files = {'crl': (filename, crl_pem, 'application/x-pem-file')}
    return testlib.post_succ(node, '/settings/crl/files', files=files)


def get_crl_files(node):
    """GET /settings/crl/files.

    Returns the parsed JSON list of uploaded file-metadata dicts.
    Each dict has: filename, checksum, uploadTimestamp, entries.
    """
    return testlib.get_succ(node, '/settings/crl/files').json()


def delete_crl_file(node, filename):
    """DELETE /settings/crl/files/:filename."""
    return testlib.delete_succ(node, f'/settings/crl/files/{filename}')


# =============================================================================
# Upload CRL callbacks
# =============================================================================


def _initial_this_update():
    """Return a thisUpdate value for initial CRL generation (now - 2 days)."""
    return (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=2))


def _next_this_update(prev):
    """Return a thisUpdate strictly after prev (prev + 1 second)."""
    return prev + datetime.timedelta(seconds=1)


def _make_upload_crl_ops(node):
    """Return (setup_fn, update_fn) callbacks that upload CRLs via the REST API.

    The returned functions have the same signature as _setup_full_crl /
    _update_full_crl and are drop-in replacements inside
    _run_crl_revocation_checks.
    The crl_dir argument is accepted but ignored — no directory needs to be
    configured on the server when using the upload API.
    """
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        this_update = _initial_this_update()
        filename = f'crl_{testlib.random_str(8)}.pem'
        crl_pem = generate_crl(ca_pem, ca_key_pem, revoked_certs,
                               expired=expired, this_update=this_update)
        upload_crl_file(node, filename, crl_pem)
        return {'filename': filename, 'revoked': list(revoked_certs),
                'last_this_update': this_update}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs, state,
               expired=False):
        state['revoked'].extend(extra_revoked_certs)
        this_update = _next_this_update(state['last_this_update'])
        crl_pem = generate_crl(ca_pem, ca_key_pem, state['revoked'],
                               expired=expired, this_update=this_update)
        upload_crl_file(node, state['filename'], crl_pem)
        state['last_this_update'] = this_update
        return state

    return setup, update


# =============================================================================
# Upload CRL callbacks — rename on update
# =============================================================================


def _make_upload_crl_ops_rename(node):
    """Upload-based CRL ops where update deletes the old file and uploads
    a fresh CRL under a new filename."""
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        this_update = _initial_this_update()
        filename = f'crl_{testlib.random_str(8)}.pem'
        crl_pem = generate_crl(ca_pem, ca_key_pem, revoked_certs,
                               expired=expired, this_update=this_update)
        upload_crl_file(node, filename, crl_pem)
        return {'filename': filename, 'revoked': list(revoked_certs),
                'last_this_update': this_update}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
               state, expired=False):
        state['revoked'].extend(extra_revoked_certs)
        this_update = _next_this_update(state['last_this_update'])
        delete_crl_file(node, state['filename'])
        new_filename = f'crl_{testlib.random_str(8)}.pem'
        crl_pem = generate_crl(ca_pem, ca_key_pem, state['revoked'],
                               expired=expired, this_update=this_update)
        upload_crl_file(node, new_filename, crl_pem)
        state['filename'] = new_filename
        state['last_this_update'] = this_update
        return state

    return setup, update


# =============================================================================
# Upload delta CRL callbacks
# =============================================================================


def _make_upload_delta_crl_ops(node):
    """Upload-based delta CRL ops: base and delta both uploaded via API.

    setup:  upload base CRL (revoked_certs in base) + empty delta
    update: overwrite delta in-place (same filename, extra_revoked added)
    """
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        this_update = _initial_this_update()
        base_filename = f'base_{testlib.random_str(8)}.pem'
        delta_filename = f'delta_{testlib.random_str(8)}.pem'
        base_pem, base_num = generate_crl_with_number(
            ca_pem, ca_key_pem, revoked_certs,
            expired=expired, this_update=this_update)
        upload_crl_file(node, base_filename, base_pem)
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, base_num, [],
            expired=expired, this_update=this_update)
        upload_crl_file(node, delta_filename, delta_pem)
        return {'base_filename': base_filename,
                'delta_filename': delta_filename,
                'base_num': base_num,
                'delta_revoked': [],
                'last_this_update': this_update}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
               state, expired=False):
        state['delta_revoked'].extend(extra_revoked_certs)
        this_update = _next_this_update(state['last_this_update'])
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, state['base_num'],
            state['delta_revoked'], expired=expired,
            this_update=this_update)
        upload_crl_file(node, state['delta_filename'], delta_pem)
        state['last_this_update'] = this_update
        return state

    return setup, update


def _make_upload_delta_crl_ops_rename(node):
    """Upload-based delta CRL ops where delta update uses a new filename."""
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        this_update = _initial_this_update()
        base_filename = f'base_{testlib.random_str(8)}.pem'
        delta_filename = f'delta_{testlib.random_str(8)}.pem'
        base_pem, base_num = generate_crl_with_number(
            ca_pem, ca_key_pem, revoked_certs,
            expired=expired, this_update=this_update)
        upload_crl_file(node, base_filename, base_pem)
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, base_num, [],
            expired=expired, this_update=this_update)
        upload_crl_file(node, delta_filename, delta_pem)
        return {'base_filename': base_filename,
                'delta_filename': delta_filename,
                'base_num': base_num,
                'delta_revoked': [],
                'last_this_update': this_update}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
               state, expired=False):
        state['delta_revoked'].extend(extra_revoked_certs)
        this_update = _next_this_update(state['last_this_update'])
        delete_crl_file(node, state['delta_filename'])
        new_delta = f'delta_{testlib.random_str(8)}.pem'
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, state['base_num'],
            state['delta_revoked'], expired=expired,
            this_update=this_update)
        upload_crl_file(node, new_delta, delta_pem)
        state['delta_filename'] = new_delta
        state['last_this_update'] = this_update
        return state

    return setup, update


# =============================================================================
# Hybrid CRL callbacks (directory + upload mixed)
# =============================================================================


def _make_hybrid_base_dir_delta_upload_ops(node):
    """Base CRL written to poll directory; delta CRL uploaded via REST API.

    Tests that directory-loaded and API-uploaded CRLs coexist in the cache
    and are both used by the OTP delta-CRL matching logic.
    """
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        this_update = _initial_this_update()
        base_filename = f'base_{testlib.random_str(8)}.pem'
        delta_filename = f'delta_{testlib.random_str(8)}.pem'
        base_pem, base_num = generate_crl_with_number(
            ca_pem, ca_key_pem, revoked_certs,
            expired=expired, this_update=this_update)
        with open(os.path.join(crl_dir, base_filename), 'w') as f:
            f.write(base_pem)
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, base_num, [],
            expired=expired, this_update=this_update)
        upload_crl_file(node, delta_filename, delta_pem)
        return {'base_filename': base_filename,
                'delta_filename': delta_filename,
                'base_num': base_num,
                'delta_revoked': [],
                'last_this_update': this_update}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
               state, expired=False):
        state['delta_revoked'].extend(extra_revoked_certs)
        this_update = _next_this_update(state['last_this_update'])
        # Base stays in directory; only the uploaded delta is updated.
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, state['base_num'],
            state['delta_revoked'], expired=expired,
            this_update=this_update)
        upload_crl_file(node, state['delta_filename'], delta_pem)
        state['last_this_update'] = this_update
        return state

    return setup, update


def _make_hybrid_dir_setup_upload_update_ops(node):
    """Initial CRL written to directory; update deletes it and uploads."""
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        this_update = _initial_this_update()
        filename = f'crl_{testlib.random_str(8)}.pem'
        crl_filepath = os.path.join(crl_dir, filename)
        generate_crl_to_file(crl_filepath, ca_pem, ca_key_pem, revoked_certs,
                             expired=expired, this_update=this_update)
        return {'filename': filename, 'revoked': list(revoked_certs),
                'in_dir': True, 'last_this_update': this_update}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
               state, expired=False):
        state['revoked'].extend(extra_revoked_certs)
        this_update = _next_this_update(state['last_this_update'])
        new_filename = f'crl_{testlib.random_str(8)}.pem'
        crl_pem = generate_crl(ca_pem, ca_key_pem, state['revoked'],
                               expired=expired, this_update=this_update)
        upload_crl_file(node, new_filename, crl_pem)
        state['filename'] = new_filename
        state['in_dir'] = False
        state['last_this_update'] = this_update
        return state

    return setup, update


def _make_hybrid_upload_setup_dir_update_ops(node):
    """Initial CRL uploaded via REST API; update writes to directory.

    Because the updated CRL has a strictly later thisUpdate than the setup
    CRL, the sort in build_dps_and_crls guarantees OTP sees the directory
    version first — no need to delete the uploaded copy.
    """
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs, expired=False):
        this_update = _initial_this_update()
        upload_filename = f'crl_{testlib.random_str(8)}.pem'
        crl_pem = generate_crl(ca_pem, ca_key_pem, revoked_certs,
                               expired=expired, this_update=this_update)
        upload_crl_file(node, upload_filename, crl_pem)
        return {'upload_filename': upload_filename,
                'dir_filename': None,
                'revoked': list(revoked_certs),
                'last_this_update': this_update}

    def update(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
               state, expired=False):
        state['revoked'].extend(extra_revoked_certs)
        this_update = _next_this_update(state['last_this_update'])
        dir_filename = f'crl_{testlib.random_str(8)}.pem'
        crl_filepath = os.path.join(crl_dir, dir_filename)
        generate_crl_to_file(crl_filepath, ca_pem, ca_key_pem, state['revoked'],
                             expired=expired, this_update=this_update)
        state['dir_filename'] = dir_filename
        state['last_this_update'] = this_update
        return state

    return setup, update


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
                     poll_interval_ms=None,
                     check_intermediate_certs=None,
                     urls=None, url_poll_interval_ms=None):
    """POST /settings/crl to configure CRL settings."""
    body = {}
    if policy_per_scope is not None:
        body['policyPerScope'] = policy_per_scope
    if directory is not None:
        body['directory'] = directory
    if poll_interval_ms is not None:
        body['dirPollIntervalMs'] = poll_interval_ms
    if check_intermediate_certs is not None:
        body['checkIntermediateCerts'] = check_intermediate_certs
    if urls is not None:
        body['urls'] = urls
    if url_poll_interval_ms is not None:
        body['urlPollIntervalMs'] = url_poll_interval_ms
    return testlib.post_succ(cluster, '/settings/crl', json=body).json()


def set_allow_expired_crls(cluster, value):
    """Set the allow_expired_crls diag/eval param on all nodes.

    ?get_param(allow_expired_crls, false) expands to:
      ns_config:search_node_with_default({cb_crl_manager, allow_expired_crls},
                                         false)
    which looks up {node, node(), {cb_crl_manager, allow_expired_crls}}.
    We must use the same nested-key form when setting.
    """
    erlang_bool = 'true' if value else 'false'
    expr = (f'ns_config:set('
            f'{{node, node(), {{cb_crl_manager, allow_expired_crls}}}}, '
            f'{erlang_bool}).')
    for node in cluster.connected_nodes:
        testlib.diag_eval(node, expr)


def get_crl_settings(cluster):
    """GET /settings/crl to retrieve current CRL settings."""
    return testlib.get_succ(cluster, '/settings/crl').json()


def get_crl_status(cluster):
    """POST /settings/crl/diagnostics/status to get CRL status from all nodes.

    Returns a dict keyed by node hostname, each containing a list of
    per-file status objects of the form:
      {"filename": "...", "source": "localDir"|"uploaded",
       "cacheStatus": "active"|"expired"|..., "entries": [...],
       "lastReload": {"result": ..., "time": ..., "errors": [...]}}
    """
    return testlib.post_succ(cluster, '/settings/crl/diagnostics/status',
                             json={}).json()


def reload_crl(node):
    """POST /node/controller/reloadCrl to force immediate CRL reload.

    Returns a list of per-file status objects (same format as the per-node
    value in the status endpoint).
    """
    return testlib.post_succ(node, '/node/controller/reloadCrl').json()


def _assert_crl_files(crl_files, expected_status):
    """Assert that at least one CRL file has the expected current status.

    crl_files is a list of status objects as returned by both the status
    and reload endpoints, where obj['cacheStatus'] is the state of the
    version currently in use.
    """
    assert len(crl_files) > 0, 'Expected at least one CRL file'
    assert any(obj.get('cacheStatus') == expected_status
               for obj in crl_files), \
        f'Expected a {expected_status} CRL file, got: {crl_files}'


def assert_crl_status(cluster, expected_status='active'):
    """Assert that at least one CRL file has the expected current status.

    Fetches CRL status from all nodes and checks that at least one file
    matches the expected status (default: 'active').
    """
    status = get_crl_status(cluster)
    print(f"CRL status: {status}")
    # Flatten the per-node lists into a single list of file status objects.
    all_files = [f for node_files in status.values()
                 if isinstance(node_files, list)
                 for f in node_files]
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


def generate_crl(ca_cert_pem, ca_key_pem, revoked_cert_pems, expired=False,
                 this_update=None):
    """Return a PEM-encoded CRL signed by the given CA.

    If expired=True, generates a CRL with nextUpdate in the past (expired).
    If this_update is given it is used as thisUpdate (last_update); otherwise
    defaults to now - 2 days.
    """
    pem, _ = generate_crl_with_number(ca_cert_pem, ca_key_pem,
                                       revoked_cert_pems, expired=expired,
                                       this_update=this_update)
    return pem


def generate_crl_with_number(ca_cert_pem, ca_key_pem, revoked_cert_pems,
                             expired=False, freshest_crl_uri=None,
                             this_update=None):
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
    if this_update is None:
        this_update = now - datetime.timedelta(days=2)

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
        .last_update(this_update)
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
                       revoked_cert_pems, expired=False, this_update=None):
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
    if this_update is None:
        this_update = now - datetime.timedelta(days=2)

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
        .last_update(this_update)
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


# =============================================================================
# Node-to-node (Erlang distribution) CRL tests
# =============================================================================


class CRLNodeToNodeTests(testlib.BaseTestSet):
    """CRL revocation tests for Erlang distribution client certificates.

    These tests verify that cb_dist:verify_client_cert/3 correctly enforces
    the node_to_node CRL policy.  Two scenarios are covered:

    OOTB certs  — both nodes use the cluster's own generated CA; the
                  verify_fun exempts these regardless of policy.
    Custom certs — both nodes use client certs signed by an external CA;
                  the CRL check applies and revoked certs are rejected.
    """

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            edition='Enterprise',
            num_nodes=2, num_connected=2,
            encryption=True, balanced=True)

    def setup(self):
        self.crl_dir = tempfile.mkdtemp()
        self.ca_ids = []
        r = testlib.get_succ(self.cluster, '/settings/autoFailover').json()
        self.af_enabled = r['enabled']
        self.af_timeout = r.get('timeout')
        if self.af_enabled:
            testlib.post_succ(self.cluster, '/settings/autoFailover',
                              data={'enabled': 'false'})

    def teardown(self):
        shutil.rmtree(self.crl_dir, ignore_errors=True)
        if self.af_enabled:
            testlib.post_succ(self.cluster, '/settings/autoFailover',
                              data={'enabled': 'true',
                                    'timeout': self.af_timeout})

    def test_teardown(self):
        # Disable clientCertVerification and restore OOTB client certs.
        for node in self.cluster.connected_nodes:
            testlib.post_succ(
                node, '/node/controller/setupNetConfig',
                data={'clientCertVerification': 'false'})

        # Wait node reconnect, otherwise regenerateCerts can timeout (no quorum)
        _wait_n2n_reconnected(self.cluster.connected_nodes,
                              expect_connected=True)

        for node in self.cluster.connected_nodes:
            testlib.post_succ(
                node, '/controller/regenerateCertificate',
                params={'forceResetCACertificate': 'false',
                        'dropUploadedCertificates': 'true'})

        # Disable CRL first so new handshakes don't fail.
        set_crl_settings(self.cluster,
                         policy_per_scope={'clientAuth': 'Disabled',
                                           'nodeToNode': 'Disabled'},
                         check_intermediate_certs=False,
                         directory="")

        # Wait for nodes to reconnect
        _wait_n2n_reconnected(self.cluster.connected_nodes,
                              expect_connected=True)

        for ca_id in self.ca_ids:
            testlib.delete(self.cluster,
                           f'/pools/default/trustedCAs/{ca_id}')
        self.ca_ids = []

    # ------------------------------------------------------------------
    # OOTB cert tests — cluster-generated certs are always exempt
    # ------------------------------------------------------------------

    def crl_n2n_disabled_ootb_test(self):
        """OOTB certs + Disabled policy: nodes stay connected."""
        self._run_n2n_crl_check('Disabled', expect_connected=True,
                                custom_cert=False)

    def crl_n2n_disabled_custom_revoked_test(self):
        """Revoked custom certs + Disabled policy: nodes stay connected.

        Disabled bypasses the CRL check entirely, so a revoked cert
        must not block the connection.
        """
        self._run_n2n_crl_check('Disabled', expect_connected=True,
                                custom_cert=True, crl_mode='revoked')

    def crl_n2n_ccv_off_revoked_require_test(self):
        """Revoked certs + Require policy + clientCertVerification off:
        nodes stay connected.

        When clientCertVerification is disabled the server uses
        verify_none and never invokes the verify_fun, so CRL policy
        has no effect even with Require and a revoked cert.
        """
        self._run_n2n_crl_check('Require', expect_connected=True,
                                custom_cert=True, crl_mode='revoked',
                                client_cert_verification=False)

    def crl_n2n_ccv_off_ootb_test(self):
        """OOTB certs + Require policy + clientCertVerification off:
        nodes stay connected.

        verify_none means no cert is requested, so the OOTB exemption
        path in the verify_fun is never even reached.
        """
        self._run_n2n_crl_check('Require', expect_connected=True,
                                custom_cert=False,
                                client_cert_verification=False)

    def crl_n2n_ccv_off_policy_disabled_test(self):
        """Revoked certs + Disabled policy + clientCertVerification off:
        nodes stay connected.

        Both the CRL policy and client cert verification are disabled;
        the connection must succeed regardless of cert status.
        """
        self._run_n2n_crl_check('Disabled', expect_connected=True,
                                custom_cert=True, crl_mode='revoked',
                                client_cert_verification=False)

    def crl_n2n_require_ootb_test(self):
        """OOTB certs + Require policy: OOTB exemption keeps nodes connected."""
        self._run_n2n_crl_check('Require', expect_connected=True,
                                custom_cert=False)

    # ------------------------------------------------------------------
    # Custom client cert tests — external CA, CRL check applies
    # ------------------------------------------------------------------

    def crl_n2n_permissive_missing_crl_test(self):
        """Permissive policy + no CRL loaded for the cert CA: nodes stay connected.

        When no CRL can be found the revocation status is undetermined;
        Permissive treats undetermined as valid.
        """
        self._run_n2n_crl_check('Permissive', expect_connected=True,
                                custom_cert=True, crl_mode='missing')

    def crl_n2n_permissive_expired_crl_test(self):
        """Permissive policy + expired CRL: nodes stay connected.

        An expired CRL makes the revocation status undetermined;
        Permissive treats undetermined as valid.
        """
        self._run_n2n_crl_check('Permissive', expect_connected=True,
                                custom_cert=True, crl_mode='expired')

    def crl_n2n_require_custom_valid_test(self):
        """Custom client certs (not revoked) + Require: nodes stay connected."""
        self._run_n2n_crl_check('Require', expect_connected=True,
                                custom_cert=True, crl_mode='valid')

    def crl_n2n_require_custom_revoked_test(self):
        """Custom client certs (revoked) + Require: nodes get disconnected."""
        self._run_n2n_crl_check('Require', expect_connected=False,
                                custom_cert=True, crl_mode='revoked')

    def crl_n2n_require_missing_crl_test(self):
        """Require policy + no CRL loaded: nodes get disconnected.

        Undetermined status is treated as a failure under Require.
        """
        self._run_n2n_crl_check('Require', expect_connected=False,
                                custom_cert=True, crl_mode='missing')

    def crl_n2n_require_expired_crl_test(self):
        """Require policy + expired CRL: nodes get disconnected.

        An expired CRL makes revocation status undetermined, which
        Require treats as a failure.
        """
        self._run_n2n_crl_check('Require', expect_connected=False,
                                custom_cert=True, crl_mode='expired')

    # ------------------------------------------------------------------
    # Server cert tests — verify_fun on the CLIENT side of distribution
    # ------------------------------------------------------------------

    def crl_n2n_server_disabled_ootb_test(self):
        """OOTB server cert + Disabled policy: nodes stay connected."""
        self._run_n2n_crl_check('Disabled', expect_connected=True,
                                custom_cert=False, cert_type='server')

    def crl_n2n_server_require_ootb_test(self):
        """OOTB server cert + Require policy: OOTB exemption keeps nodes
        connected."""
        self._run_n2n_crl_check('Require', expect_connected=True,
                                custom_cert=False, cert_type='server')

    def crl_n2n_server_require_valid_test(self):
        """Custom server cert (not revoked) + Require: nodes stay connected."""
        self._run_n2n_crl_check('Require', expect_connected=True,
                                custom_cert=True, crl_mode='valid',
                                cert_type='server')

    def crl_n2n_server_require_revoked_test(self):
        """Custom server cert (revoked) + Require: nodes get disconnected."""
        self._run_n2n_crl_check('Require', expect_connected=False,
                                custom_cert=True, crl_mode='revoked',
                                cert_type='server')

    def crl_n2n_server_disabled_revoked_test(self):
        """Revoked server cert + Disabled policy: nodes stay connected."""
        self._run_n2n_crl_check('Disabled', expect_connected=True,
                                custom_cert=True, crl_mode='revoked',
                                cert_type='server')

    def crl_n2n_server_permissive_missing_crl_test(self):
        """Custom server cert + Permissive + no CRL: nodes stay connected."""
        self._run_n2n_crl_check('Permissive', expect_connected=True,
                                custom_cert=True, crl_mode='missing',
                                cert_type='server')

    def crl_n2n_server_require_missing_crl_test(self):
        """Custom server cert + Require + no CRL: nodes get disconnected."""
        self._run_n2n_crl_check('Require', expect_connected=False,
                                custom_cert=True, crl_mode='missing',
                                cert_type='server')

    def crl_n2n_server_require_expired_crl_test(self):
        """Custom server cert + Require + expired: nodes get disconnected."""
        self._run_n2n_crl_check('Require', expect_connected=False,
                                custom_cert=True, crl_mode='expired',
                                cert_type='server')

    # ------------------------------------------------------------------
    # HTTP connection tests — exercises node_to_node_crl_verify/3 via
    # tls_peer_verification_client_opts (all outgoing HTTPS connections
    # from ns_server to other nodes go through this path).
    # Only node2's node cert is customised; the test connects from
    # node1 (TLS client) to node2 (TLS server).
    # ------------------------------------------------------------------

    def crl_n2n_http_require_ootb_test(self):
        """OOTB server cert + Require: HTTP connection stays connected.

        OOTB node certs are signed by the cluster CA and exempted.
        """
        self._run_n2n_http_crl_check('Require', expect_connected=True,
                                     custom_cert=False)

    def crl_n2n_http_require_valid_test(self):
        """Custom server cert (not revoked) + Require: HTTP connected."""
        self._run_n2n_http_crl_check('Require', expect_connected=True,
                                     custom_cert=True, crl_mode='valid')

    def crl_n2n_http_require_revoked_test(self):
        """Custom server cert (revoked) + Require: HTTP connection fails."""
        self._run_n2n_http_crl_check('Require', expect_connected=False,
                                     custom_cert=True, crl_mode='revoked')

    def crl_n2n_http_disabled_revoked_test(self):
        """Revoked server cert + Disabled policy: HTTP stays connected."""
        self._run_n2n_http_crl_check('Disabled', expect_connected=True,
                                     custom_cert=True, crl_mode='revoked')

    def crl_n2n_http_permissive_missing_crl_test(self):
        """Custom server cert + Permissive + no CRL: HTTP stays connected.

        Undetermined status is treated as valid under Permissive.
        """
        self._run_n2n_http_crl_check('Permissive', expect_connected=True,
                                     custom_cert=True, crl_mode='missing')

    def crl_n2n_http_require_missing_crl_test(self):
        """Custom server cert + Require + no CRL: HTTP connection fails.

        Undetermined status is treated as failure under Require.
        """
        self._run_n2n_http_crl_check('Require', expect_connected=False,
                                     custom_cert=True, crl_mode='missing')

    def _run_n2n_http_crl_check(self, policy, expect_connected,
                                custom_cert=False, crl_mode=None):
        """Test CRL checking for outgoing HTTP connections via
        tls_peer_verification_client_opts / node_to_node_crl_verify/3.

        A custom NODE cert is loaded on node2 (the server); node1 (the
        client) makes a direct TLS connection to node2's HTTPS port
        using tls_client_opts, which now includes the CRL verify_fun.
        Only node2's cert is customised — this is one-directional.
        """
        if crl_mode is None:
            crl_mode = 'valid'

        node1 = self.cluster.connected_nodes[0]
        node2 = self.cluster.connected_nodes[1]
        crl_file = os.path.join(self.crl_dir, 'n2n_http_crl.pem')

        ca_pem, ca_key_pem = generate_root_ca()
        self.ca_ids = load_multiple_cas(node1, [ca_pem])
        if custom_cert:
            cert2_pem, _ = generate_and_load_node_cert(node2, ca_pem,
                                                       ca_key_pem)

            if crl_mode == 'revoked':
                generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [cert2_pem])
            elif crl_mode == 'valid':
                generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [])
            elif crl_mode == 'expired':
                generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [],
                                     expired=True)
            elif crl_mode == 'missing':
                # no CRL for this CA
                pass
        else:
            generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [])

        crl_settings = {'policy_per_scope': {'nodeToNode': policy,
                                             'clientAuth': 'Disabled'},
                        'poll_interval_ms': 5000,
                        'directory': self.crl_dir}
        set_crl_settings(self.cluster, **crl_settings)
        if custom_cert and crl_mode in ('valid', 'revoked'):
            assert_crl_status(self.cluster, expected_status='active')

        # Wait for both nodes to have the new policy in ETS before
        # initiating the test connection.
        expected_policy = policy.lower()
        for node in [node1, node2]:
            _wait_crl_policy(node, 'node_to_node', expected_policy)

        connected = _http_request_to_node(node1, node2, self.cluster)
        assert connected == expect_connected, \
            (f"Expected {'connected' if expect_connected else 'not connected'}"
             f" but got {'connected' if connected else 'not connected'}")

    def _run_n2n_crl_check(self, policy, expect_connected,
                           custom_cert=False, crl_mode=None,
                           client_cert_verification=True, cert_type='client'):
        """Run a node-to-node CRL check scenario.
        Provision nodes with certs and CRLs according to the parameters,
        set the CRL policy, and verify whether the nodes stay connected or
        get disconnected as expected.

        cert_type: 'client' (default) — exercises verify_client_cert/3
                                        (server checks connecting node's
                                        client cert)
                   'server'           — exercises verify_server_cert/3
                                        (client checks server's node cert)
        crl_mode (only relevant when custom_cert=True):
          None / 'valid'  — valid CRL, cert not revoked
          'revoked'       — valid CRL, both certs revoked
          'missing'       — no CRL loaded for the cert CA (undetermined)
          'expired'       — expired CRL, cert not revoked (undetermined)
        """
        if crl_mode is None:
            crl_mode = 'valid'
        if not custom_cert and crl_mode != 'valid':
            raise ValueError("crl_mode other than 'valid' is not applicable "
                             "when custom_cert is False")

        node1 = self.cluster.connected_nodes[0]
        node2 = self.cluster.connected_nodes[1]

        crl_file = os.path.join(self.crl_dir, 'n2n_crl.pem')

        ca_pem, ca_key_pem = generate_root_ca()
        self.ca_ids = load_multiple_cas(node1, [ca_pem])
        if custom_cert:

            if cert_type == 'server':
                cert1_pem, _ = generate_and_load_node_cert(node1, ca_pem,
                                                           ca_key_pem)
                cert2_pem, _ = generate_and_load_node_cert(node2, ca_pem,
                                                           ca_key_pem)
            else:
                cert1_pem, _ = generate_and_load_internal_client_cert(
                                 node1, ca_pem, ca_key_pem, 'internal')
                cert2_pem, _ = generate_and_load_internal_client_cert(
                                 node2, ca_pem, ca_key_pem, 'internal')

            if crl_mode == 'revoked':
                # Revoke both certs so BOTH directions of the handshake
                # fail, giving a deterministic disconnection result.
                generate_crl_to_file(crl_file, ca_pem, ca_key_pem,
                                     [cert1_pem, cert2_pem])
            elif crl_mode == 'valid':
                generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [])
            elif crl_mode == 'expired':
                # Expired CRL (nextUpdate in the past): revocation status
                # is undetermined for all certs under this CA.
                generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [],
                                     expired=True)
            elif crl_mode == 'missing':
                # Write nothing — no CRL for this CA.
                pass
        else:
            # OOTB certs are already loaded; just generate a CRL for the CA.
            generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [])

        # Enable or disable clientCertVerification.  When disabled the
        # server uses verify_none and never calls the verify_fun, so CRL
        # policy has no effect regardless of cert status.
        ccv_value = 'true' if client_cert_verification else 'false'
        for node in [node1, node2]:
            testlib.post_succ(
                node, '/node/controller/setupNetConfig',
                data={'clientCertVerification': ccv_value})

        # Wait for the nodes to reconnect with the new clientCertVerification
        # At this point the connection should always succeed
        _wait_n2n_reconnected([node1, node2], expect_connected=True)

        crl_settings = {'policy_per_scope': {'nodeToNode': policy,
                                             'clientAuth': 'Disabled'},
                        'poll_interval_ms': 5000,
                        'directory': self.crl_dir}
        set_crl_settings(self.cluster, **crl_settings)
        if custom_cert and crl_mode in ('valid', 'revoked'):
            assert_crl_status(self.cluster, expected_status='active')

        # Wait until both nodes have written the new node_to_node policy
        # to cb_crl_cache ETS before restarting TLS.
        expected_policy = policy.lower()
        for node in [node1, node2]:
            _wait_crl_policy(node, 'node_to_node', expected_policy)

        _wait_n2n_reconnected([node1, node2], expect_connected=expect_connected)

        # Testing is done, now we should restore connectivity
        if expect_connected:
            # already connected
            return

        if custom_cert:
            # Generate CRL if it is missing now.
            # Otherwise nodes will not reconnect
            if crl_mode == 'missing':
                generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [])
            elif crl_mode == 'revoked':
                # Generate new certificates for nodes to replace
                # the revoked ones
                if cert_type == 'server':
                    cert1_pem, _ = generate_and_load_node_cert(node1, ca_pem,
                                                               ca_key_pem)
                    cert2_pem, _ = generate_and_load_node_cert(node2, ca_pem,
                                                               ca_key_pem)
                else:
                    cert1_pem, _ = generate_and_load_internal_client_cert(
                                    node1, ca_pem, ca_key_pem, 'internal')
                    cert2_pem, _ = generate_and_load_internal_client_cert(
                                    node2, ca_pem, ca_key_pem, 'internal')
            elif crl_mode == 'expired':
                # In this case we should update CRL as it has expired
                generate_crl_to_file(crl_file, ca_pem, ca_key_pem, [])

def _http_request_to_node(from_node, to_node, cluster):
    """Make an HTTPS GET from from_node to to_node via
    menelaus_rest:json_request_hilevel — the same internal HTTP client
    all ns_server node-to-node calls use.  Returns True when any HTTP
    response is received (TLS handshake succeeded), False when the
    request fails at the TLS level (e.g. cert revoked).
    """
    host = to_node.host
    port = to_node.tls_service_port()
    user = cluster.admin_user()
    password = cluster.admin_password()
    # ?HIDE(X) expands to fun () -> X end, so HiddenAuth must be a
    # zero-arity fun that returns the auth term.
    code = (
        f"case menelaus_rest:json_request_hilevel("
        f"get,"
        f" {{https, \"{host}\", {port}, \"/pools\"}},"
        f" fun () -> {{basic_auth, \"{user}\", \"{password}\"}} end,"
        f" []) of"
        f" {{ok, _}} -> ok;"
        f" _ -> error"
        f" end."
    )
    r = testlib.diag_eval(from_node, code)
    return r.text.strip() == 'ok'


def _wait_crl_policy(node, scope, expected_policy, timeout_s=15):
    """Poll until cb_crl_cache reports the expected policy for scope.

    Chronicle replication is async; the verify_fun reads policy from ETS,
    so TLS must not be restarted before the policy lands in ETS.
    scope is an Erlang atom string, e.g. 'node_to_node'.
    expected_policy is a lowercase string: 'disabled','permissive','strict',
    'require'.
    """
    def check():
        r = testlib.diag_eval(
            node,
            f"cb_crl_cache:get_policy({scope}).")
        return r.text.strip() == expected_policy

    testlib.poll_for_condition(
        check, sleep_time=0.2, timeout=timeout_s,
        msg=f'{scope} policy={expected_policy} on {node}')


def _wait_n2n_reconnected(nodes, expect_connected=True, timeout_s=30):
    """Drop connection between nodes and poll until node1 and node2 are
       (or are not) distribution-connected."""

    assert len(nodes) == 2, "Exactly 2 nodes must be provided"

    testlib.diag_eval(nodes[0], f"[net_kernel:disconnect(N) || N <- nodes()].")

    node2_otp = testlib.diag_eval(nodes[1], 'node().').text.strip()

    def check():
        r = testlib.diag_eval(nodes[0], f"net_adm:ping({node2_otp}).")
        return (r.text.strip() == 'pong') == expect_connected

    testlib.poll_for_condition(
        check, sleep_time=1.0, timeout=timeout_s,
        msg=f'n2n {"connected" if expect_connected else "disconnected"}')


# =============================================================================
# HTTP server helper for URL-based CRL tests
# =============================================================================


class CRLHttpServer:
    """Local HTTP server that serves configurable content over HTTP.

    Serves independent content per request path, so a single server can
    back several CRL URLs at once (e.g. base + delta, or one CRL per CA).

    Lifecycle: use as a context manager (starts in __enter__, stops in
    __exit__) or call start()/stop() explicitly (e.g. from test
    setup/teardown when the server must outlive a single 'with' block).

    The server honours ETag / If-None-Match caching: each path has a
    monotonically increasing version counter used as its ETag.  Updating a
    path's content increments its version so the CRL manager receives fresh
    content even when it holds a cached ETag from a previous request.

    The single-path helpers (set_content/set_unavailable/url) operate on the
    default path '/crl.pem' for backwards compatibility.
    """

    _DEFAULT_PATH = '/crl.pem'

    def __init__(self):
        self._lock = threading.Lock()
        # path -> {'content': bytes, 'status': int, 'version': int}
        self._paths = {}
        self._httpd = None
        self._thread = None
        self._port = None

    def set_path_content(self, path, data, status_code=200):
        """Set the response body for a path and bump its ETag version."""
        if isinstance(data, str):
            data = data.encode()
        with self._lock:
            prev = self._paths.get(path)
            version = (prev['version'] + 1) if prev else 1
            self._paths[path] = {'content': data, 'status': status_code,
                                 'version': version}
        print(f"CRLHttpServer: set content for {path} "
              f"(status={status_code}, {len(data)} bytes, version={version})")

    def set_content(self, data, status_code=200):
        """Replace the default-path response body and bump its ETag."""
        self.set_path_content(self._DEFAULT_PATH, data, status_code)

    def set_unavailable(self):
        """Make the default path respond with 503 Service Unavailable."""
        with self._lock:
            prev = self._paths.get(self._DEFAULT_PATH)
            content = prev['content'] if prev else b''
            version = (prev['version'] + 1) if prev else 1
            self._paths[self._DEFAULT_PATH] = {'content': content,
                                               'status': 503,
                                               'version': version}
        print(f"CRLHttpServer: set {self._DEFAULT_PATH} unavailable "
              f"(status=503, version={version})")

    def url_for(self, path):
        return f'http://127.0.0.1:{self._port}{path}'

    @property
    def url(self):
        return self.url_for(self._DEFAULT_PATH)

    def start(self):
        server = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                with server._lock:
                    entry = server._paths.get(self.path)
                if entry is None:
                    self.send_response(404)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                content = entry['content']
                status = entry['status']
                version = entry['version']
                etag = f'"{version}"'
                inm = self.headers.get('If-None-Match', '')
                if inm == etag and status == 200:
                    self.send_response(304)
                    self.end_headers()
                    return
                self.send_response(status)
                self.send_header('ETag', etag)
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, fmt, *args):
                pass

        # Bind to port 0 to let the OS assign a free port.
        self._httpd = socketserver.TCPServer(
            ('127.0.0.1', 0), _Handler)
        self._port = self._httpd.server_address[1]
        self._thread = threading.Thread(
            target=self._httpd.serve_forever)
        self._thread.daemon = True
        self._thread.start()
        print(f"CRLHttpServer: started on 127.0.0.1:{self._port}")
        return self

    def stop(self):
        if self._httpd is not None:
            port = self._port
            self._httpd.shutdown()
            self._httpd.server_close()
            self._thread.join()
            self._httpd = None
            self._thread = None
            print(f"CRLHttpServer: stopped (was on 127.0.0.1:{port})")

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


# =============================================================================
# CRL bad-CRL status helper
# =============================================================================


def assert_crl_file_load_error(result, fname, expected_cache_status=None,
                               expected_reload_result=None,
                               expected_error_num=0,
                               expected_error=None):
    print(f'status: {result}')
    bad_file = next(
        (f for f in result
            if f.get('filename') == fname), None)
    assert bad_file is not None, \
        f'{fname} not in reload result: {result}'
    assert bad_file.get('cacheStatus') == expected_cache_status, \
        f'Expected cache status {expected_cache_status}, got: {bad_file}'
    last_reload = bad_file.get('lastReload', {})
    assert last_reload.get('result') == expected_reload_result, \
        f'Expected "{expected_reload_result}" result, got: {last_reload}'
    assert len(last_reload.get('errors', [])) == expected_error_num, \
        f'Unexpected errors num: {len(last_reload.get("errors", []))}'

    if expected_error is not None:
        assert any(expected_error in e for e in last_reload['errors']), \
            f'Unexpected errors: {last_reload["errors"]}'


def assert_crl_load_error(status_list, expected_cache_status=None):
    """Assert that at least one CRL file has a non-active error status.

    status_list is a list of per-file status dicts as returned by
    reload_crl() or extracted from get_crl_status().

    If expected_cache_status is provided, asserts that at least one
    file matches that exact cacheStatus value.  Otherwise, asserts
    that no file has cacheStatus == 'active'.
    """
    assert len(status_list) > 0, \
        f'Expected at least one CRL file in status: {status_list}'
    if expected_cache_status is not None:
        assert any(f.get('cacheStatus') == expected_cache_status
                   for f in status_list), \
            (f'Expected cacheStatus={expected_cache_status!r},'
             f' got: {status_list}')
    else:
        assert all(f.get('cacheStatus') != 'active'
                   for f in status_list), \
            f'Expected no active CRL, got: {status_list}'


# =============================================================================
# Negative tests: bad CRL across all three loading paths
# =============================================================================


class CRLBadCRLTests(testlib.BaseTestSet):
    """Negative tests for bad CRL data.

    Three loading paths:
      Upload API  — bad CRL is rejected immediately with HTTP 400.
      Local dir   — bad CRL file appears in reload status with an
                    error cacheStatus; replacing it recovers to active.
      URL-based   — HTTP server returning bad data also produces an
                    error status; serving a good CRL recovers.
    """

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition='Enterprise')

    def setup(self):
        # Expired CRLs must be rejected.  CRLTests.setup sets this
        # to True, so be explicit here.
        set_allow_expired_crls(self.cluster, False)

    def teardown(self):
        set_allow_expired_crls(self.cluster, False)

    def test_teardown(self):
        node = self.cluster.connected_nodes[0]
        set_crl_settings(
            self.cluster,
            policy_per_scope={'clientAuth': 'Disabled',
                              'nodeToNode': 'Disabled'},
            directory='', urls=[])
        for f in get_crl_files(node):
            delete_crl_file(node, f['filename'])

    # ------------------------------------------------------------------
    # Upload API — synchronous validation
    # ------------------------------------------------------------------

    def upload_garbage_content_test(self):
        """Uploading non-CRL bytes returns HTTP 400 with decode error."""
        node = self.cluster.connected_nodes[0]
        garbage = b'\x00\xFF' * 32 + b'not a crl'
        files = {'crl': ('bad.pem', garbage, 'application/x-pem-file')}
        r = testlib.post_fail(node, '/settings/crl/files', files=files,
                              expected_code=400)
        error = r.json().get('error', '')
        print(f'upload_garbage_content error: {error}')
        assert 'Failed to decode CRL: Invalid CRL' in error, \
            f'Unexpected error: {error!r}'

    def upload_untrusted_issuer_test(self):
        """CRL signed by an untrusted CA returns HTTP 400."""
        node = self.cluster.connected_nodes[0]
        untrusted_pem, untrusted_key = generate_root_ca()
        crl_pem = generate_crl(untrusted_pem, untrusted_key, [])
        files = {'crl': ('untrusted.pem', crl_pem.encode(),
                         'application/x-pem-file')}
        r = testlib.post_fail(node, '/settings/crl/files', files=files,
                              expected_code=400)
        error = r.json().get('error', '')
        print(f'upload_untrusted_issuer error: {error}')
        assert 'issuer not trusted' in error.lower(), \
            f'Unexpected error: {error!r}'

    def upload_expired_crl_test(self):
        """Uploading an expired CRL returns HTTP 400."""
        node = self.cluster.connected_nodes[0]
        ca_pem, ca_key_pem = generate_root_ca()
        ca_ids = load_multiple_cas(node, [ca_pem])
        try:
            crl_pem = generate_crl(ca_pem, ca_key_pem, [], expired=True)
            files = {'crl': ('expired.pem', crl_pem.encode(),
                             'application/x-pem-file')}
            r = testlib.post(node, '/settings/crl/files', files=files)
            testlib.assert_eq(r.status_code, 400,
                              name='expired CRL upload status')
            error = r.json().get('error', '')
            print(f'upload_expired_crl error: {error}')
            assert 'CRL expired' in error, \
                f'Expected CRL expired error, got: {error!r}'
        finally:
            for ca_id in ca_ids:
                testlib.delete(node, f'/pools/default/trustedCAs/{ca_id}')

    def upload_bad_request_test(self):
        """Invalid upload requests return HTTP 400 with specific errors."""
        node = self.cluster.connected_nodes[0]

        # 1. Wrong Content-Type (not multipart/form-data).
        r = testlib.post_fail(node, '/settings/crl/files',
                              data=b'notcrl',
                              headers={'Content-Type': 'text/plain'},
                              expected_code=400)
        error = r.json().get('error', '')
        print(f'bad_request wrong-ct error: {error}')
        assert 'multipart' in error.lower(), \
            f'Expected multipart error, got: {error!r}'

        # 2. Invalid filename (path traversal attempt).
        r = testlib.post_fail(node, '/settings/crl/files',
                              files={'crl': ('../bad.pem', b'\x00',
                                             'application/octet-stream')},
                              expected_code=400)
        error = r.json().get('error', '')
        print(f'bad_request invalid-fn error: {error}')
        assert 'invalid filename' in error.lower(), \
            f'Expected invalid-filename error, got: {error!r}'

        # 3. Multiple files in one request.
        r = testlib.post_fail(node, '/settings/crl/files',
                              files=[('crl', ('a.pem', b'\x00',
                                              'application/octet-stream')),
                                     ('crl', ('b.pem', b'\x00',
                                              'application/octet-stream'))],
                              expected_code=400)
        error = r.json().get('error', '')
        print(f'bad_request multi-file error: {error}')
        assert 'multiple' in error.lower(), \
            f'Expected multiple-files error, got: {error!r}'

        # 4. Multipart with no file part (only a plain form field).
        body = (
            b'--testbnd\r\n'
            b'Content-Disposition: form-data; name="field"\r\n'
            b'\r\n'
            b'value\r\n'
            b'--testbnd--\r\n'
        )
        r = testlib.post_fail(node, '/settings/crl/files',
                              data=body,
                              headers={'Content-Type':
                                       'multipart/form-data; boundary=testbnd'},
                              expected_code=400)
        error = r.json().get('error', '')
        print(f'bad_request no-file error: {error}')
        assert 'no file' in error.lower(), \
            f'Expected no-file error, got: {error!r}'

    # ------------------------------------------------------------------
    # Local directory — asynchronous status
    # ------------------------------------------------------------------

    def local_dir_garbage_crl_test(self):
        """Garbage file in CRL dir produces error status; replacing it
        with a valid CRL recovers to active status."""
        node = self.cluster.connected_nodes[0]
        ca_pem, ca_key_pem = generate_root_ca()
        ca_ids = load_multiple_cas(node, [ca_pem])
        crl_dir = tempfile.mkdtemp()
        try:
            crl_path = os.path.join(crl_dir, 'bad.pem')
            with open(crl_path, 'wb') as f:
                f.write(b'not a crl file')

            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             poll_interval_ms=1000,
                             directory=crl_dir)

            result = reload_crl(node)
            assert_crl_file_load_error(result, 'bad.pem',
                                       expected_cache_status='notLoaded',
                                       expected_reload_result='failed',
                                       expected_error_num=1,
                                       expected_error='Failed to decode file')

            # Replace with a valid CRL → recovery to active.
            generate_crl_to_file(crl_path, ca_pem, ca_key_pem, [])
            result = reload_crl(node)
            assert_crl_file_load_error(result, 'bad.pem',
                                       expected_cache_status='active',
                                       expected_reload_result='loaded',
                                       expected_error_num=0)
        finally:
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             directory='')
            for ca_id in ca_ids:
                testlib.delete(node, f'/pools/default/trustedCAs/{ca_id}')
            shutil.rmtree(crl_dir, ignore_errors=True)

    def local_dir_untrusted_issuer_test(self):
        """CRL from an untrusted CA in the directory → untrusted status."""
        node = self.cluster.connected_nodes[0]
        untrusted_pem, untrusted_key = generate_root_ca()
        crl_dir = tempfile.mkdtemp()
        try:
            crl_path = os.path.join(crl_dir, 'untrusted.pem')
            generate_crl_to_file(crl_path, untrusted_pem,
                                 untrusted_key, [])

            set_crl_settings(
                self.cluster,
                policy_per_scope={'clientAuth': 'Disabled',
                                  'nodeToNode': 'Disabled'},
                poll_interval_ms=1000,
                directory=crl_dir)

            result = reload_crl(node)
            assert_crl_file_load_error(result, 'untrusted.pem',
                                       expected_cache_status='notLoaded',
                                       expected_reload_result='failed',
                                       expected_error_num=1,
                                       expected_error='CRL issuer not trusted')
        finally:
            set_crl_settings(
                self.cluster,
                policy_per_scope={'clientAuth': 'Disabled',
                                  'nodeToNode': 'Disabled'},
                directory='')
            shutil.rmtree(crl_dir, ignore_errors=True)

    def local_dir_expired_test(self):
        """Expired CRL in the directory → expired status."""
        node = self.cluster.connected_nodes[0]
        trusted_pem, trusted_key = generate_root_ca()
        ca_ids = load_multiple_cas(node, [trusted_pem])
        crl_dir = tempfile.mkdtemp()
        try:
            crl_path = os.path.join(crl_dir, 'expired.pem')
            generate_crl_to_file(crl_path, trusted_pem, trusted_key, [],
                                 expired=True)

            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             poll_interval_ms=1000,
                             directory=crl_dir)

            result = reload_crl(node)
            assert_crl_file_load_error(result, 'expired.pem',
                                       expected_cache_status='notLoaded',
                                       expected_reload_result='failed',
                                       expected_error_num=1,
                                       expected_error='CRL expired')
            generate_crl_to_file(crl_path, trusted_pem, trusted_key, [])

            # Should re-read it in 1 second (hence the poll):
            testlib.poll_for_condition(
                lambda: assert_crl_file_load_error(
                            get_crl_status(node)[node.hostname()],
                            'expired.pem',
                            expected_cache_status='active',
                            expected_reload_result='loaded',
                            expected_error_num=0),
                sleep_time=0.5, attempts=20, retry_on_assert=True)
        finally:
            set_crl_settings(
                self.cluster,
                policy_per_scope={'clientAuth': 'Disabled',
                                  'nodeToNode': 'Disabled'},
                directory='')
            for ca_id in ca_ids:
                testlib.delete(node, f'/pools/default/trustedCAs/{ca_id}')
            shutil.rmtree(crl_dir, ignore_errors=True)

    # ------------------------------------------------------------------
    # URL-based — asynchronous status
    # ------------------------------------------------------------------

    def url_garbage_content_test(self):
        """URL serving garbage → error status; switch to valid CRL →
        recovery to active."""
        node = self.cluster.connected_nodes[0]
        ca_pem, ca_key_pem = generate_root_ca()
        ca_ids = load_multiple_cas(node, [ca_pem])
        try:
            with CRLHttpServer() as srv:
                srv.set_content(b'not a crl at all')

                set_crl_settings(
                    self.cluster,
                    policy_per_scope={'clientAuth': 'Disabled',
                                      'nodeToNode': 'Disabled'},
                    urls=[srv.url],
                    url_poll_interval_ms=1000)

                result = reload_crl(node)
                assert_crl_file_load_error(
                    result, srv.url,
                    expected_cache_status='notLoaded',
                    expected_reload_result='failed',
                    expected_error_num=1,
                    expected_error='Failed to decode file. Reason: Invalid CRL')

                # Switch to a valid CRL → recovery.
                valid_crl = generate_crl(ca_pem, ca_key_pem, [])
                srv.set_content(valid_crl.encode())

                result = reload_crl(node)
                assert_crl_file_load_error(result, srv.url,
                                           expected_cache_status='active',
                                           expected_reload_result='loaded',
                                           expected_error_num=0)

                # Switch back to bad crl (it stays active now)
                srv.set_content(b'not a crl at all')

                result = reload_crl(node)
                assert_crl_file_load_error(
                    result, srv.url,
                    expected_cache_status='active',
                    expected_reload_result='failed',
                    expected_error_num=1,
                    expected_error='Failed to decode file. Reason: Invalid CRL')
        finally:
            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             urls=[])
            for ca_id in ca_ids:
                testlib.delete(node, f'/pools/default/trustedCAs/{ca_id}')

    def url_http_error_test(self):
        """URL returning HTTP 404 → failed status with HTTP error detail."""
        node = self.cluster.connected_nodes[0]
        ca_pem, ca_key_pem = generate_root_ca()
        ca_ids = load_multiple_cas(node, [ca_pem])
        try:
            with CRLHttpServer() as srv:
                srv.set_content(b'Not Found', status_code=404)

                set_crl_settings(
                    self.cluster,
                    policy_per_scope={'clientAuth': 'Disabled',
                                      'nodeToNode': 'Disabled'},
                    urls=[srv.url],
                    url_poll_interval_ms=1000)

                result = reload_crl(node)
                assert_crl_file_load_error(
                    result, srv.url,
                    expected_cache_status='notLoaded',
                    expected_reload_result='failed',
                    expected_error_num=1,
                    expected_error='HTTP 404 Not Found')

                valid_crl = generate_crl(ca_pem, ca_key_pem, [])
                srv.set_content(valid_crl.encode())

                # Should re-read it in 1 second (hence the poll):
                testlib.poll_for_condition(
                    lambda: assert_crl_file_load_error(
                                get_crl_status(node)[node.hostname()], srv.url,
                                expected_cache_status='active',
                                expected_reload_result='loaded',
                                expected_error_num=0),
                    sleep_time=0.5, attempts=20, retry_on_assert=True)
        finally:
            set_crl_settings(
                self.cluster,
                policy_per_scope={'clientAuth': 'Disabled',
                                  'nodeToNode': 'Disabled'},
                urls=[])
            for ca_id in ca_ids:
                testlib.delete(
                    node, f'/pools/default/trustedCAs/{ca_id}')

    def url_untrusted_issuer_test(self):
        """URL serving a CRL from an untrusted CA → untrusted status."""
        node = self.cluster.connected_nodes[0]
        untrusted_pem, untrusted_key = generate_root_ca()
        ca_ids = []
        try:
            with CRLHttpServer() as srv:
                untrusted_crl = generate_crl(untrusted_pem, untrusted_key, [])
                srv.set_content(untrusted_crl.encode())

                set_crl_settings(self.cluster,
                                 policy_per_scope={'clientAuth': 'Disabled',
                                                   'nodeToNode': 'Disabled'},
                                 urls=[srv.url],
                                 url_poll_interval_ms=1000)

                result = reload_crl(node)
                assert_crl_file_load_error(
                    result, srv.url,
                    expected_cache_status='notLoaded',
                    expected_reload_result='failed',
                    expected_error_num=1,
                    expected_error='CRL issuer not trusted')

                ca_ids = load_multiple_cas(node, [untrusted_pem])

                # Should re-read it in 1 second (hence the poll):
                testlib.poll_for_condition(
                    lambda: assert_crl_file_load_error(
                                get_crl_status(node)[node.hostname()], srv.url,
                                expected_cache_status='active',
                                expected_reload_result='loaded',
                                expected_error_num=0),
                    sleep_time=0.5, attempts=20, retry_on_assert=True)
        finally:
            set_crl_settings(
                self.cluster,
                policy_per_scope={'clientAuth': 'Disabled',
                                  'nodeToNode': 'Disabled'},
                urls=[])
            for ca_id in ca_ids:
                testlib.delete(
                    node, f'/pools/default/trustedCAs/{ca_id}')

    def url_expired_issuer_test(self):
        """URL serving an expired CRL → expired status."""
        node = self.cluster.connected_nodes[0]
        trusted_pem, trusted_key = generate_root_ca()
        ca_ids = load_multiple_cas(node, [trusted_pem])
        try:
            with CRLHttpServer() as srv:
                expired_crl = generate_crl(trusted_pem, trusted_key, [],
                                           expired=True)
                srv.set_content(expired_crl.encode())

                set_crl_settings(self.cluster,
                                 policy_per_scope={'clientAuth': 'Disabled',
                                                   'nodeToNode': 'Disabled'},
                                 urls=[srv.url],
                                 url_poll_interval_ms=1000)

                result = reload_crl(node)
                assert_crl_file_load_error(
                    result, srv.url,
                    expected_cache_status='notLoaded',
                    expected_reload_result='failed',
                    expected_error_num=1,
                    expected_error='CRL expired')

                good_crl = generate_crl(trusted_pem, trusted_key, [])
                srv.set_content(good_crl.encode())

                # Should re-read it in 1 second (hence the poll):
                testlib.poll_for_condition(
                    lambda: assert_crl_file_load_error(
                                get_crl_status(node)[node.hostname()], srv.url,
                                expected_cache_status='active',
                                expected_reload_result='loaded',
                                expected_error_num=0),
                    sleep_time=0.5, attempts=20, retry_on_assert=True)
        finally:
            set_crl_settings(
                self.cluster,
                policy_per_scope={'clientAuth': 'Disabled',
                                  'nodeToNode': 'Disabled'},
                urls=[])
            for ca_id in ca_ids:
                testlib.delete(
                    node, f'/pools/default/trustedCAs/{ca_id}')
