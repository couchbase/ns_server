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

    def _run_crl_revocation_checks(self, setup_crl, update_crl):
        """Shared test body for CRL revocation tests.

        setup_crl(crl_dir, ca_pem, ca_key, revoked_certs) -> state
            writes initial CRL file(s) revoking the given certs
        update_crl(crl_dir, ca_pem, ca_key, extra_certs, state)
            adds extra_certs to the revoked list and rewrites CRL file(s)
        """
        # All requests go to a single node so that client-cert-auth settings
        # changes are seen immediately (the setting is not instantly
        # synchronised across the cluster).
        node = self.cluster.connected_nodes[0]

        user1 = testlib.random_str(8)
        user2 = testlib.random_str(8)
        password = testlib.random_str(8)

        crl_dir = tempfile.mkdtemp()
        ca_ids = []

        try:
            # ------------------------------------------------------------------
            # Step 1: Generate a two-level PKI:
            #   Root CA  ->  Intermediate CA  ->  client cert 1 / client cert 2
            # ------------------------------------------------------------------
            root_ca_pem, root_ca_key_pem = generate_root_ca()
            inter_ca_pem, inter_ca_key_pem = generate_intermediate_ca(
                root_ca_pem, root_ca_key_pem)
            client_cert1_pem, client_key1_pem = generate_client_cert_cn(
                inter_ca_pem, inter_ca_key_pem, user1)
            client_cert2_pem, client_key2_pem = generate_client_cert_cn(
                inter_ca_pem, inter_ca_key_pem, user2)

            # ------------------------------------------------------------------
            # Step 2: Create RBAC users (one per client cert)
            # ------------------------------------------------------------------
            testlib.put_succ(
                self.cluster, f'/settings/rbac/users/local/{user1}',
                data={'roles': 'ro_admin', 'password': password})
            testlib.put_succ(
                self.cluster, f'/settings/rbac/users/local/{user2}',
                data={'roles': 'ro_admin', 'password': password})

            # ------------------------------------------------------------------
            # Step 3: Configure client cert auth – use CN as the username
            # ------------------------------------------------------------------
            testlib.toggle_client_cert_auth(
                node, enabled=True, mandatory=False,
                prefixes=[{'delimiter': '', 'path': 'subject.cn',
                           'prefix': ''}])

            # ------------------------------------------------------------------
            # Step 4: Load Root CA and Intermediate CA as trusted certs.
            # ------------------------------------------------------------------
            ca_ids = load_multiple_cas(node, [root_ca_pem, inter_ca_pem])

            # ------------------------------------------------------------------
            # Step 5: Verify both client certs can authenticate
            # ------------------------------------------------------------------
            with (client_cert_file(client_cert1_pem, inter_ca_pem,
                                   client_key1_pem) as cert1_path,
                  client_cert_file(client_cert2_pem, inter_ca_pem,
                                   client_key2_pem) as cert2_path):

                r = testlib.get_succ(node, '/whoami', https=True,
                                     auth=None, cert=cert1_path).json()
                testlib.assert_eq(r['id'], user1,
                                  name='user1 /whoami before CRL')

                r = testlib.get_succ(node, '/whoami', https=True,
                                     auth=None, cert=cert2_path).json()
                testlib.assert_eq(r['id'], user2,
                                  name='user2 /whoami before CRL')

                # --------------------------------------------------------------
                # Step 6: Generate CRL(s) that revoke client cert 1
                # --------------------------------------------------------------
                crl_state = setup_crl(crl_dir, inter_ca_pem,
                                      inter_ca_key_pem,
                                      [client_cert1_pem])

                # --------------------------------------------------------------
                # Step 7: Enable CRL – "Require" policy for clientAuth scope.
                # --------------------------------------------------------------
                set_crl_settings(self.cluster,
                                 policy_per_scope={'clientAuth': 'Require',
                                                   'nodeToNode': 'Disabled'},
                                 poll_interval_ms=5000,
                                 directory=crl_dir)

                # Verify CRL status shows the loaded CRL as active
                assert_crl_status(self.cluster, expected_status='active')

                # --------------------------------------------------------------
                # Step 8: Verify that client cert 1 (revoked) is now rejected
                # and client cert 2 (not revoked) still works.
                # --------------------------------------------------------------
                assert_cert_rejected(
                    lambda: try_client_auth(node, cert1_path))

                r = try_client_auth(node, cert2_path).json()
                testlib.assert_eq(r['id'], user2,
                                  name='user2 /whoami after CRL')

                # --------------------------------------------------------------
                # Step 9: Update CRL(s) to also revoke cert2, call reload API,
                # and verify both certs are now revoked.
                # --------------------------------------------------------------
                update_crl(crl_dir, inter_ca_pem, inter_ca_key_pem,
                           [client_cert2_pem], crl_state)

                # Call reload API to force immediate CRL refresh
                assert_reload_crl(node, expected_status='active')

                # Both certs should now be rejected
                assert_cert_rejected(
                    lambda: try_client_auth(node, cert1_path))
                assert_cert_rejected(
                    lambda: try_client_auth(node, cert2_path))

        finally:
            # Disable client cert auth first so the cleanup requests below can
            # use plain password auth without hitting certificate requirements.
            testlib.toggle_client_cert_auth(node, enabled=False)

            testlib.ensure_deleted(self.cluster,
                                   f'/settings/rbac/users/local/{user1}')
            testlib.ensure_deleted(self.cluster,
                                   f'/settings/rbac/users/local/{user2}')

            for ca_id in ca_ids:
                testlib.delete(node, f'/pools/default/trustedCAs/{ca_id}')

            set_crl_settings(self.cluster,
                             policy_per_scope={'clientAuth': 'Disabled',
                                               'nodeToNode': 'Disabled'},
                             directory="")

            shutil.rmtree(crl_dir, ignore_errors=True)


# =============================================================================
# Full CRL callbacks
# =============================================================================


def _setup_full_crl(crl_dir, ca_pem, ca_key_pem, revoked_certs):
    """Write a full CRL revoking the given certs. Returns state."""
    filename = f'crl_{testlib.random_str(8)}.pem'
    generate_crl_to_file(os.path.join(crl_dir, filename), ca_pem, ca_key_pem,
                         revoked_certs)
    return {'filename': filename, 'revoked': list(revoked_certs)}


def _update_full_crl(crl_dir, ca_pem, ca_key_pem, extra_revoked_certs,
                     state):
    """Update full CRL adding extra certs to revoked list."""
    state['revoked'].extend(extra_revoked_certs)
    generate_crl_to_file(os.path.join(crl_dir, state['filename']), ca_pem,
                         ca_key_pem, state['revoked'])
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
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs):
        base_filename = f'base_{testlib.random_str(8)}.pem'
        delta_filename = f'delta_{testlib.random_str(8)}.pem'
        delta_uri = f'file://{os.path.join(crl_dir, delta_filename)}'
        base_pem, base_num = generate_crl_with_number(
            ca_pem, ca_key_pem, revoked_certs,
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

    def update(crl_dir, ca_pem, ca_key_pem, extra_certs, state):
        state['delta_revoked'].extend(extra_certs)
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, state['base_num'],
            state['delta_revoked'])
        with open(os.path.join(crl_dir, state['delta_filename']), 'w') as f:
            f.write(delta_pem)
        return state

    return setup, update


def _make_delta_crl_ops_both_in_delta():
    """Factory for delta CRL ops: all revocations carried in the delta CRL.

    Returns (setup_fn, update_fn) where:
    - setup: creates empty base CRL + delta CRL (revoked_certs)
    - update: adds extra_certs to the delta CRL
    """
    def setup(crl_dir, ca_pem, ca_key_pem, revoked_certs):
        base_filename = f'base_{testlib.random_str(8)}.pem'
        delta_filename = f'delta_{testlib.random_str(8)}.pem'
        delta_uri = f'file://{os.path.join(crl_dir, delta_filename)}'
        base_pem, base_num = generate_crl_with_number(
            ca_pem, ca_key_pem, [],
            freshest_crl_uri=delta_uri)
        with open(os.path.join(crl_dir, base_filename), 'w') as f:
            f.write(base_pem)
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, base_num, revoked_certs)
        with open(os.path.join(crl_dir, delta_filename), 'w') as f:
            f.write(delta_pem)
        return {'base_filename': base_filename,
                'delta_filename': delta_filename,
                'base_num': base_num,
                'delta_revoked': list(revoked_certs)}

    def update(crl_dir, ca_pem, ca_key_pem, extra_certs, state):
        state['delta_revoked'].extend(extra_certs)
        delta_pem = generate_delta_crl(
            ca_pem, ca_key_pem, state['base_num'],
            state['delta_revoked'])
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


def generate_crl(ca_cert_pem, ca_key_pem, revoked_cert_pems):
    """Return a PEM-encoded CRL signed by the given CA."""
    pem, _ = generate_crl_with_number(ca_cert_pem, ca_key_pem,
                                       revoked_cert_pems)
    return pem


def generate_crl_with_number(ca_cert_pem, ca_key_pem, revoked_cert_pems,
                             freshest_crl_uri=None):
    """Return (pem, crl_number) for a CRL signed by the given CA.

    revoked_cert_pems is a list of PEM strings whose serial numbers will be
    added to the revocation list.

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

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
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
                       revoked_cert_pems):
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

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=1))
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
