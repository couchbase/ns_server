# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import ipaddress
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import testlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID

scriptdir = sys.path[0]
certs_path = os.path.join(scriptdir, 'resources', 'test_certs')
generate_cert_path = os.path.join(scriptdir, '..', 'deps', 'gocode', 'bin',
                                  'generate_cert')
openssl_path = os.path.join(scriptdir, '..', '..', 'install', 'bin', 'openssl')

from testlib.test_tag_decorator import tag, Tag

class CertLoadTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition='Enterprise',
                                           min_num_nodes=3,
                                           encryption=True,
                                           balanced=True)

    def setup(self):
        # Need to remove extras,
        regenerate_certs_and_remove_unused_generated_cas(self.cluster)

        ca_path = os.path.join(certs_path(), 'test_CA.pem')
        with open(ca_path, 'r') as f:
            self.ca_pem = f.read()
        ca_key = os.path.join(certs_path(), 'test_CA.pkey')
        with open(ca_key, 'r') as f:
            self.ca_key = f.read()

        self.node_addr = self.cluster.connected_nodes[0].addr()
        self.loaded_CA_ids = load_ca(self.cluster.connected_nodes[0],
                                     self.ca_pem)

    def teardown(self):
        testlib.post_succ(self.cluster, '/controller/regenerateCertificate',
                          params={'forceResetCACertificate': 'false',
                                  'dropUploadedCertificates': 'true'})

        def delete(ca_id):
            r = testlib.delete(self.cluster,
                               f'/pools/default/trustedCAs/{ca_id}')
            # Retry if 503
            assert r.status_code != 503
            return r

        for ca_id in self.loaded_CA_ids:
            r_final = testlib.poll_for_condition(
                lambda: delete(ca_id),
                sleep_time=0.5,
                timeout=60,
                retry_on_assert=True)

            testlib.assert_eq(r_final.status_code, 204,
                              f"status for deletion of {ca_id}")

    def rsa_private_key_pkcs1_test(self):
        self.generate_and_load_cert('rsa')

    def rsa_private_key_pkcs8_test(self):
        self.generate_and_load_cert('rsa', pkcs8=True)

    def rsa_private_key_pkcs8_encrypted_test(self):
        self.generate_and_load_cert('rsa', pkcs8=True,
                                         passphrase=testlib.random_str(8))

    def ec_private_key_test(self):
        self.generate_and_load_cert('ec')

    def ec_private_key_pkcs8_test(self):
        self.generate_and_load_cert('ec', pkcs8=True)

    def ec_private_key_pkcs8_encrypted_test(self):
        self.generate_and_load_cert('ec', pkcs8=True,
                                         passphrase=testlib.random_str(8))

    def client_cert_with_rsa_key_test(self):
        self.generate_and_load_cert('rsa', is_client=True)

    def client_cert_with_ec_key_test(self):
        self.generate_and_load_cert('ec', is_client=True)

    def client_cert_with_rsa_pkcs8_key_test(self):
        self.generate_and_load_cert('rsa', is_client=True, pkcs8=True)

    def client_cert_with_ec_pkcs8_key_test(self):
        self.generate_and_load_cert('ec', is_client=True, pkcs8=True)

    def client_cert_with_rsa_pkcs8_encrypted_key_test(self):
        self.generate_and_load_cert('rsa', is_client=True, pkcs8=True,
                                    passphrase=testlib.random_str(8))

    def client_cert_with_ec_pkcs8_encrypted_key_test(self):
        self.generate_and_load_cert('ec', is_client=True, pkcs8=True,
                                    passphrase=testlib.random_str(8))

    def unencrypted_key_with_passphrase_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_node_certs(node.addr(), self.ca_pem, self.ca_key)
        load_cert(node, cert, key, passphrase=testlib.random_str(8),
                  is_client=False,
                  expected_error='private key is not encrypted')

    def client_cert_unencrypted_key_with_passphrase_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_internal_client_cert(self.ca_pem, self.ca_key,
                                                  'test_name')
        load_cert(node, cert, key, passphrase=testlib.random_str(8),
                  is_client=True,
                  expected_error='private key is not encrypted')

    # An empty passphrase is a passphrase like any other, it is stored and
    # passed to services, so it must be rejected for an unencrypted key too
    def unencrypted_key_with_empty_passphrase_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_node_certs(node.addr(), self.ca_pem, self.ca_key)
        load_cert(node, cert, key, passphrase='', is_client=False,
                  expected_error='private key is not encrypted')

    # pkcs8 keys can be encrypted with an empty passphrase, such a key needs
    # that passphrase to be loaded, and must not be mistaken for a plain one
    def empty_passphrase_encrypted_key_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_node_certs(node.addr(), self.ca_pem, self.ca_key)
        key = to_pkcs8(key, '')
        load_cert(node, cert, key, passphrase=None, is_client=False,
                  expected_error='Check password')
        load_cert(node, cert, key, passphrase='', is_client=False)

    def client_pkcs12_with_rsa_key_test(self):
        self.generate_and_load_pkcs12_cert('rsa', is_client=True)

    def client_pkcs12_with_ec_key_test(self):
        self.generate_and_load_pkcs12_cert('ec', is_client=True)

    def client_pkcs12_with_encrypted_rsa_key_test(self):
        self.generate_and_load_pkcs12_cert('rsa', is_client=True,
                                           passphrase=testlib.random_str(8))

    def client_pkcs12_with_encrypted_ec_key_test(self):
        self.generate_and_load_pkcs12_cert('ec', is_client=True,
                                           passphrase=testlib.random_str(8))

    def critical_eku_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_eku(node.addr(),
                                           self.ca_pem, self.ca_key,
                                           critical=True)
        load_cert(node, cert, key, passphrase=None, is_client=False)

    def client_cert_with_critical_eku_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_eku(node.addr(),
                                           self.ca_pem, self.ca_key,
                                           is_client=True, critical=True)
        load_cert(node, cert, key, passphrase=None, is_client=True)

    def critical_eku_multiple_purposes_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_eku(
            node.addr(), self.ca_pem, self.ca_key,
            purposes=['serverAuth', 'clientAuth'], critical=True)
        load_cert(node, cert, key, passphrase=None, is_client=False)

    def missing_eku_purpose_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_eku(
            node.addr(), self.ca_pem, self.ca_key,
            purposes=['clientAuth'], critical=True)
        load_cert(node, cert, key, passphrase=None, is_client=False,
                  expected_error='serverAuth')

    def client_cert_missing_eku_purpose_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_eku(
            node.addr(), self.ca_pem, self.ca_key, is_client=True,
            purposes=['serverAuth'], critical=True)
        load_cert(node, cert, key, passphrase=None, is_client=True,
                  expected_error='clientAuth')

    # non-critical eku purpose should still be validated
    def non_critical_missing_eku_purpose_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_eku(
            node.addr(), self.ca_pem, self.ca_key,
            purposes=['clientAuth'], critical=False)
        load_cert(node, cert, key, passphrase=None, is_client=False,
                  expected_error='serverAuth')

    def client_cert_non_critical_missing_eku_purpose_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_eku(
            node.addr(), self.ca_pem, self.ca_key, is_client=True,
            purposes=['serverAuth'], critical=False)
        load_cert(node, cert, key, passphrase=None, is_client=True,
                  expected_error='clientAuth')

    # anyExtendedKeyUsage is not accepted in place of explicit purposes by OTP
    def any_eku_purpose_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_eku(
            node.addr(), self.ca_pem, self.ca_key,
            purposes=['any'], critical=True)
        load_cert(node, cert, key, passphrase=None, is_client=False,
                  expected_error='serverAuth')

    # a structurally malformed eku extension is rejected with a 400 rather
    # than crashing chain path validation with a 500 (MB-72954)
    def malformed_eku_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_malformed_eku(node.addr(),
                                                    self.ca_pem, self.ca_key)
        load_cert(node, cert, key, passphrase=None, is_client=False,
                  expected_error='Malformed certificate')

    def client_cert_malformed_eku_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_cert_with_malformed_eku(node.addr(),
                                                    self.ca_pem, self.ca_key,
                                                    is_client=True)
        load_cert(node, cert, key, passphrase=None, is_client=True,
                  expected_error='Malformed certificate')

    # a malformed extension on an intermediate (not the leaf) is likewise
    # caught during path validation rather than crashing with a 500 (MB-72954)
    def malformed_intermediate_eku_test(self):
        node = self.cluster.connected_nodes[0]
        cert, key = generate_malformed_intermediate_chain(
            node.addr(), self.ca_pem, self.ca_key)
        load_cert(node, cert, key, passphrase=None, is_client=False,
                  expected_error='Malformed certificate')

    def generate_cert_with_cn_prefix_test(self):
        cert, _ = generate_node_certs(self.node_addr, self.ca_pem,
                                      self.ca_key, key_type='rsa',
                                      generate_leaf=False)
        c = x509.load_pem_x509_certificate(cert.encode('utf-8'),
                                           default_backend())
        common_names = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = None
        for common_name in common_names:
            common_name = common_name.value
        assert c.not_valid_after > datetime.now()
        assert c.not_valid_before < datetime.now()
        assert common_name and common_name.startswith("Couchbase Server")

    def generate_and_load_cert(self, key_type, node=None, is_client=False,
                               pkcs8=False, passphrase=None):
        if node is None:
            node = self.cluster.connected_nodes[0]
        node_addr = node.addr()
        if is_client:
            cert, key = generate_internal_client_cert(self.ca_pem, self.ca_key,
                                                      'test_name')
        else:
            cert, key = generate_node_certs(node_addr,
                                            self.ca_pem, self.ca_key,
                                            key_type=key_type)
        if pkcs8 == False:
            assert passphrase is None, \
                   'encryption is supported only for pkcs8 keys'
        if pkcs8:
            key = to_pkcs8(key, passphrase)
        return load_cert(node, cert, key, passphrase,
                         is_client=is_client)

    def pkcs12_rsa_key_test(self):
        self.generate_and_load_pkcs12_cert('rsa')

    def pkcs12_ec_key_test(self):
        self.generate_and_load_pkcs12_cert('ec')

    def pkcs12_encrypted_rsa_key_test(self):
        self.generate_and_load_pkcs12_cert('rsa',
                                           passphrase=testlib.random_str(8))

    def pkcs12_encrypted_ec_key_test(self):
        self.generate_and_load_pkcs12_cert('ec',
                                           passphrase=testlib.random_str(8))

    ## Reload node certificates is disruptive to the system. So if the cert
    ## is the same as what is in use we skip the reloading.
    @tag(Tag.LowUrgency)
    def short_circuit_reloading_node_cert_test(self):

        def load_cert_return_timestamp(force=False):
            load_cert(self.cluster.connected_nodes[0], cert, key,
                      passphrase=None, is_client=False, force_reload=force)
            r = testlib.get_succ(self.cluster.connected_nodes[0],
                                 f'/pools/default/certificate/'
                                 f'node/{self.cluster.connected_nodes[0]}')
            r = r.json()
            return r['loadTimestamp']

        cert, key = generate_node_certs(self.node_addr,
                                        self.ca_pem, self.ca_key)

        ts1 = load_cert_return_timestamp(force=False)
        time.sleep(2)
        ts2 = load_cert_return_timestamp(force=False)
        ## Because the certs haven't changed the returned timestamp will
        ## not have changed.
        assert (ts1 == ts2)
        ts3 = load_cert_return_timestamp(force=True)
        ## The reload was forced so the returned timestamp will be different.
        assert (ts1 != ts3)

    @tag(Tag.LowUrgency)
    def short_circuit_reloading_client_cert_test(self):

        def load_cert_return_timestamp(force=False):
            node = self.cluster.connected_nodes[0]
            load_cert(node, cert, key, passphrase=None, is_client=True,
                      force_reload=force)
            return get_node_cert(node, is_client=True)['loadTimestamp']

        cert, key = generate_internal_client_cert(self.ca_pem, self.ca_key,
                                                  'test_name')

        ts1 = load_cert_return_timestamp(force=False)
        time.sleep(2)
        ts2 = load_cert_return_timestamp(force=False)
        ## The cert has not changed, so it was not reloaded.
        assert ts1 == ts2, f'client cert was reloaded: {ts1} -> {ts2}'
        ts3 = load_cert_return_timestamp(force=True)
        ## Unless the reload is forced.
        assert ts1 != ts3, 'forced reload of the client cert did nothing'

    def generate_and_load_pkcs12_cert(self, key_type, passphrase=None,
                                      is_client=False):
        if is_client:
            cert, key = generate_internal_client_cert(self.ca_pem, self.ca_key,
                                                      'test_name')
        else:
            cert, key = generate_node_certs(self.node_addr,
                                            self.ca_pem, self.ca_key,
                                            key_type=key_type)

        node_data_path = self.cluster.connected_nodes[0].data_path()
        inbox_dir = os.path.join(node_data_path, 'inbox')
        os.makedirs(inbox_dir, exist_ok=True)
        filename = 'couchbase_client.p12' if is_client else 'couchbase.p12'
        pkcs12_path = os.path.join(inbox_dir, filename)
        try:
            write_pkcs12(cert, key, pkcs12_path,
                         passphrase=passphrase)
            data = {'privateKeyPassphrase': {'type': 'plain',
                                             'password': passphrase}} \
                   if passphrase is not None else None
            endpoint = 'reloadClientCertificate' if is_client \
                       else 'reloadCertificate'
            testlib.post_succ(self.cluster, f'/node/controller/{endpoint}',
                              json=data)
        finally:
            if os.path.exists(pkcs12_path):
                os.remove(pkcs12_path)

    @tag(Tag.LowUrgency)
    def regen_certs_test(self):
        node_certs_before = self.load_custom_certs()

        original_trusted_cas = get_trusted_CAs(self.cluster)
        original_trusted_ca_pems = [ca.get('pem')
                                    for ca in original_trusted_cas]
        try:
            new_ca_pem = regenerate_certs(self.cluster,
                                          force_reset_ca=False,
                                          drop_uploaded_certs=False)
            assert new_ca_pem in original_trusted_ca_pems, \
                "CA regenerated when force_reset=false "
            # CA should not be regenerated, and should not become trusted
            assert_trusted_CAs_unchanged(self.cluster, original_trusted_cas)
            assert_no_certs_changed(self.cluster, node_certs_before, None)
        finally:
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    @tag(Tag.LowUrgency)
    def regen_and_drop_certs_test(self):
        node_certs_before = self.load_custom_certs()

        original_trusted_cas = get_trusted_CAs(self.cluster)
        original_trusted_ca_pems = [ca.get('pem')
                                    for ca in original_trusted_cas]
        try:
            new_ca_pem = regenerate_certs(self.cluster,
                                          force_reset_ca=False,
                                          drop_uploaded_certs=True)
            # Since we're dropping the uploaded certs, but not resetting the ca,
            # the new_ca_pem won't actually be used by the new node/client certs
            wait_all_nodes_updated(self.cluster, node_certs_before, None)
            assert new_ca_pem in original_trusted_ca_pems, \
                "CA regenerated when force_reset=false "
            # CA should not be regenerated
            assert_trusted_CAs_unchanged(self.cluster, original_trusted_cas)
        finally:
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    @tag(Tag.LowUrgency)
    def regen_force_reset_certs_test(self):
        node_certs_before = self.load_custom_certs()

        original_trusted_cas = get_trusted_CAs(self.cluster)
        original_trusted_ca_pems = [ca.get('pem')
                                    for ca in original_trusted_cas]
        try:
            new_ca_pem = regenerate_certs(self.cluster,
                                          force_reset_ca=True,
                                          drop_uploaded_certs=False)
            assert_no_certs_changed(self.cluster, node_certs_before, new_ca_pem)
            # CA should be regenerated, and newly trusted
            assert new_ca_pem not in original_trusted_ca_pems, \
                "CA not regenerated when force_reset=true"
            assert_CA_newly_trusted(self.cluster, original_trusted_cas,
                                    new_ca_pem)
        finally:
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    @tag(Tag.LowUrgency)
    def regen_force_reset_and_drop_certs_test(self):
        node_certs_before = self.load_custom_certs()

        original_trusted_cas = get_trusted_CAs(self.cluster)
        original_trusted_ca_pems = [ca.get('pem')
                                    for ca in original_trusted_cas]
        try:
            new_ca_pem = regenerate_certs(self.cluster,
                                          force_reset_ca=True,
                                          drop_uploaded_certs=True)
            wait_all_nodes_updated(self.cluster, node_certs_before, new_ca_pem)

            # CA should be regenerated, and newly trusted
            assert new_ca_pem not in original_trusted_ca_pems, \
                "CA not regenerated when force_reset=true"
            assert_CA_newly_trusted(self.cluster, original_trusted_cas,
                                    new_ca_pem)
        finally:
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    @tag(Tag.LowUrgency)
    def regen_certs_with_untrusted_ca_test(self):
        node_certs_before = self.load_custom_certs()

        original_trusted_cas = get_trusted_CAs(self.cluster)
        original_trusted_ca_pems = [ca.get('pem')
                                    for ca in original_trusted_cas]
        original_trusted_generated_cas = [ca for ca in original_trusted_cas
                                          if ca.get('type') == 'generated']
        original_trusted_generated_ca_ids = [
            ca.get('id') for ca in original_trusted_generated_cas]
        try:
            # Remove the generated ca, to test re-trusting
            [ootb_ca] = original_trusted_generated_ca_ids
            testlib.delete_succ(self.cluster,
                                f'/pools/default/trustedCAs/{ootb_ca}',
                                expected_code=204)
            # Get updated ca lists, for comparison
            trusted_cas_before = get_trusted_CAs(self.cluster)
            trusted_generated_ca_pems_before = \
                [ca.get('pem')
                 for ca in trusted_cas_before
                 if ca.get('type') == 'generated']

            new_ca_pem = regenerate_certs(self.cluster,
                                          force_reset_ca=False,
                                          drop_uploaded_certs=False)
            assert_no_certs_changed(self.cluster, node_certs_before, None)
            # CA should not be regenerated, and shouldn't become trusted (as the
            # certs weren't force-dropped
            assert new_ca_pem not in trusted_generated_ca_pems_before, \
                "CA wasn't re-trusted, instead an already trusted pem was used"
            assert new_ca_pem in original_trusted_ca_pems, \
                "CA regenerated when force_reset=false"
            assert_trusted_CAs_unchanged(self.cluster, trusted_cas_before)
        finally:
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    @tag(Tag.LowUrgency)
    def regen_and_drop_certs_with_untrusted_ca_test(self):
        node_certs_before = self.load_custom_certs()

        original_trusted_cas = get_trusted_CAs(self.cluster)
        original_trusted_ca_pems = [ca.get('pem')
                                    for ca in original_trusted_cas]
        original_trusted_generated_cas = [ca for ca in original_trusted_cas
                                          if ca.get('type') == 'generated']
        original_trusted_generated_ca_ids = [
            ca.get('id') for ca in original_trusted_generated_cas]

        try:
            # Remove the generated ca, to test re-trusting
            ootb_ca = original_trusted_generated_ca_ids[0]
            testlib.delete_succ(self.cluster,
                                f'/pools/default/trustedCAs/{ootb_ca}',
                                expected_code=204)

            # Get updated ca lists, for comparison
            trusted_cas_before = get_trusted_CAs(self.cluster)
            trusted_generated_ca_pems_before = \
                [ca.get('pem')
                 for ca in trusted_cas_before
                 if ca.get('type') == 'generated']

            new_ca_pem = regenerate_certs(self.cluster,
                                          force_reset_ca=False,
                                          drop_uploaded_certs=True)
            wait_all_nodes_updated(self.cluster, node_certs_before, new_ca_pem)

            assert new_ca_pem not in trusted_generated_ca_pems_before, \
                "CA not regenerated when untrusted"
            assert new_ca_pem in original_trusted_ca_pems, \
                "CA regenerated when force_reset=false "
            # CA should not be regenerated, but should become trusted again.
            # Explicitly check 'pem' instead of 'id', since the id could change
            # when re-trusting the ca.
            assert_trusted_CAs_unchanged(self.cluster, original_trusted_cas,
                                         'pem')
            assert_CA_newly_trusted(self.cluster, trusted_cas_before,
                                    new_ca_pem)
        finally:
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    @tag(Tag.LowUrgency)
    def regen_force_reset_certs_with_untrusted_ca_test(self):
        node_certs_before = self.load_custom_certs()

        original_trusted_cas = get_trusted_CAs(self.cluster)
        original_trusted_ca_pems = [ca.get('pem')
                                    for ca in original_trusted_cas]
        original_trusted_generated_cas = [ca for ca in original_trusted_cas
                                          if ca.get('type') == 'generated']
        original_trusted_generated_ca_ids = [
            ca.get('id') for ca in original_trusted_generated_cas]

        try:
            # Remove the generated ca, to test re-trusting
            ootb_ca = original_trusted_generated_ca_ids[0]
            testlib.delete_succ(self.cluster,
                                f'/pools/default/trustedCAs/{ootb_ca}',
                                expected_code=204)

            # Get updated ca lists, for comparison
            trusted_cas_before = get_trusted_CAs(self.cluster)
            trusted_generated_ca_pems_before = \
                [ca.get('pem')
                 for ca in trusted_cas_before
                 if ca.get('type') == 'generated']

            new_ca_pem = regenerate_certs(self.cluster,
                                          force_reset_ca=True,
                                          drop_uploaded_certs=False)
            assert_no_certs_changed(self.cluster, node_certs_before, new_ca_pem)

            # CA should be regenerated, and newly trusted
            assert new_ca_pem not in trusted_generated_ca_pems_before, \
                "CA not regenerated when force_reset=true"
            assert new_ca_pem not in original_trusted_ca_pems, \
                "CA re-trusted and not regenerated when force_reset=true"
            assert_CA_newly_trusted(self.cluster, original_trusted_cas,
                                    new_ca_pem)
            assert_CA_newly_trusted(self.cluster, trusted_cas_before,
                                    new_ca_pem)
        finally:
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    @tag(Tag.LowUrgency)
    def regen_force_reset_certs_and_drop_with_untrusted_ca_test(self):
        node_certs_before = self.load_custom_certs()

        original_trusted_cas = get_trusted_CAs(self.cluster)
        original_trusted_ca_pems = [ca.get('pem')
                                    for ca in original_trusted_cas]
        original_trusted_generated_cas = [ca for ca in original_trusted_cas
                                          if ca.get('type') == 'generated']
        original_trusted_generated_ca_ids = [
            ca.get('id') for ca in original_trusted_generated_cas]

        try:
            # Remove the last generated ca
            ootb_ca = original_trusted_generated_ca_ids[0]
            testlib.delete_succ(self.cluster,
                                f'/pools/default/trustedCAs/{ootb_ca}',
                                expected_code=204)

            trusted_cas_before = get_trusted_CAs(self.cluster)

            trusted_generated_ca_pems_before = [ca.get('pem')
                                      for ca in trusted_cas_before
                                      if ca.get('type') == 'generated']

            new_ca_pem = regenerate_certs(self.cluster,
                                          force_reset_ca=True,
                                          drop_uploaded_certs=True)
            wait_all_nodes_updated(self.cluster, node_certs_before, new_ca_pem)
            # CA should be regenerated, and newly trusted
            assert new_ca_pem not in trusted_generated_ca_pems_before, \
                "CA not regenerated when force_reset=true"
            assert new_ca_pem not in original_trusted_ca_pems, \
                "CA re-trusted and not regenerated when force_reset=true"
            assert_CA_newly_trusted(self.cluster, original_trusted_cas,
                                    new_ca_pem)
            assert_CA_newly_trusted(self.cluster, trusted_cas_before,
                                    new_ca_pem)
        finally:
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    # Resetting the self-generated CA whilst a node is unreachable would leave
    # that node unable to reconnect once it returns, so the reset is refused
    # unless allowUnreachableNodes overrides that
    @tag(Tag.LowUrgency)
    def regen_refused_when_node_unreachable_test(self):
        node_certs_before = get_node_certs(self.cluster)
        master = self.cluster.connected_nodes[0]
        victim = self.cluster.connected_nodes[-1]
        assert victim != master, "need a second connected node to stop"
        # Disable auto-failover since we're not testing the failed over case
        auto_failover_settings = self.cluster.disable_auto_failover()
        try:
            self.cluster.stop_node(victim)
            wait_any_node_unhealthy(master)

            # A CA reset is refused whilst a node is unreachable
            r = testlib.post_fail(master, '/controller/regenerateCertificate',
                                  expected_code=503,
                                  params={'forceResetCACertificate': 'true'})
            testlib.assert_in('allowUnreachableNodes', r.text, r)

            # Reusing the existing CA creates no new CA, so it is not blocked
            testlib.post_succ(master, '/controller/regenerateCertificate',
                              params={'forceResetCACertificate': 'false',
                                      'dropUploadedCertificates': 'false'})

            # The override lets the reset proceed
            testlib.post_succ(master, '/controller/regenerateCertificate',
                              params={'forceResetCACertificate': 'true',
                                      'allowUnreachableNodes': 'true'})
        finally:
            self.cluster.restart_node(victim)
            self.cluster.wait_for_nodes_to_be_healthy()
            regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)
            self.cluster.maybe_enable_auto_failover(auto_failover_settings)

    @tag(Tag.LowUrgency)
    def regen_refused_when_failed_over_node_unreachable_test(self):
        node_certs_before = get_node_certs(self.cluster)
        master = self.cluster.connected_nodes[0]
        victim = self.cluster.connected_nodes[-1]
        assert victim != master, "need a second connected node to fail over"
        node_failed_over = False
        try:
            self.cluster.stop_node(victim)
            wait_any_node_unhealthy(master)
            # A hard failover leaves the node in the cluster, so it can be
            # recovered later and still needs the new CA
            node_failed_over = (
                    self.cluster.failover_node(victim, graceful=False)
                    .status_code == 200)

            r = testlib.post_fail(master, '/controller/regenerateCertificate',
                                  expected_code=503,
                                  params={'forceResetCACertificate': 'true'})
            testlib.assert_in('allowUnreachableNodes', r.text, r)
        finally:
            self.cluster.restart_node(victim)
            self.cluster.wait_for_nodes_to_be_healthy()
            if node_failed_over:
                self.cluster.recover_node(victim, recovery_type='full',
                                          do_rebalance=True)
                regenerate_certs_and_remove_unused_generated_cas(self.cluster,
                                                             node_certs_before)

    def load_custom_certs(self):
        node_certs = []
        for node in self.cluster.connected_nodes:
            node_cert = self.generate_and_load_cert('rsa', node=node,
                                                    is_client=False)
            client_cert = self.generate_and_load_cert('rsa', node=node,
                                                      is_client=True)
            node_certs.append((node, node_cert, client_cert))
        return node_certs


def wait_all_nodes_updated(cluster, node_certs_before, new_ca_pem):
    def all_nodes_updated():
        # Only check the node certs if we know the new ca
        # TODO: do this properly
        if new_ca_pem is not None and len(node_certs_before) > 0:
            trusted_cas = get_trusted_CAs(cluster)
            [new_ca_details] = [ca for ca in trusted_cas
                                if ca['pem'] == new_ca_pem]
            node_certs = new_ca_details['nodes']
            assert len(node_certs) == len(node_certs_before), \
                f"Not all node certs using new ca ({node_certs})"
            client_cert_nodes = new_ca_details['client_cert_nodes']
            assert len(client_cert_nodes) == len(node_certs_before), \
                f"Not all client certs using new ca ({client_cert_nodes})"
        # Confirm that node certs are regenerated
        for (node, node_cert, client_cert) in node_certs_before:
            assert_cert_regenerated(node, node_cert)
            assert_cert_regenerated(node, client_cert, is_client=True)
    testlib.poll_for_condition(all_nodes_updated, 1, timeout=60,
                               retry_on_assert=True)


def assert_no_certs_changed(cluster, node_certs_before, new_ca_pem):
    if new_ca_pem is not None:
        trusted_cas = get_trusted_CAs(cluster)
        [new_ca_details] = [ca for ca in trusted_cas
                            if ca['pem'] == new_ca_pem]
        node_certs = new_ca_details['nodes']
        assert len(node_certs) == 0, \
            f"Node certs unexpectedly using the new ca ({node_certs})"
        client_cert_nodes = new_ca_details['client_cert_nodes']
        assert len(client_cert_nodes) == 0, \
            f"Client certs unexpectedly using the new ca ({client_cert_nodes})"
    # Confirm that node certs are unchanged
    for (node, node_cert, client_cert) in node_certs_before:
        assert_cert_unchanged(node, node_cert)
        assert_cert_unchanged(node, client_cert, is_client=True)


# Regenerate certs and tidy up trusted certs by removing unused ones
def regenerate_certs_and_remove_unused_generated_cas(cluster,
                                                     node_certs_before=None):
    if node_certs_before is None:
        node_certs_before = get_node_certs(cluster)
    new_ca_pem = regenerate_certs(cluster)
    wait_all_nodes_updated(cluster, node_certs_before, new_ca_pem)
    for trusted_ca in get_trusted_CAs(cluster):
        if (trusted_ca['type'] == 'generated' and
                trusted_ca['pem'] != new_ca_pem):
            ca_id = trusted_ca['id']
            testlib.delete_succ(cluster,
                                f'/pools/default/trustedCAs/{ca_id}',
                                expected_code=204)


def assert_CA_newly_trusted(cluster, trusted_cas_before, expected_new_pem):
    trusted_cas_after = get_trusted_CAs(cluster)
    ca_ids_before = [ca['id'] for ca in trusted_cas_before]
    new_cas = [ca for ca in trusted_cas_after if ca['id'] not in ca_ids_before]
    assert len(new_cas) == 1, f'expected 1 new CA, got {len(new_cas)}'
    new_ca_props = new_cas[0]
    assert new_ca_props['pem'] == expected_new_pem, \
           'unexpected pem in new CA'


def assert_trusted_CAs_unchanged(cluster, trusted_cas_before, identifier='id'):
    trusted_cas_after = get_trusted_CAs(cluster)
    ids_before = [ca[identifier] for ca in trusted_cas_before]
    ids_after = [ca[identifier] for ca in trusted_cas_after]
    assert ids_before == ids_after, 'CAs changed'


def assert_cert_regenerated(node, prev_cert_before, is_client=False):
    node_cert_after = get_node_cert(node, is_client=is_client)
    assert node_cert_after['type'] == 'generated', \
           'node_cert_after type != generated'
    assert node_cert_after['pem'] != prev_cert_before['pem'], \
           'node_cert_after pem == node_cert_before pem'


def assert_cert_unchanged(node, prev_cert_before, is_client=False):
    node_cert_after = get_node_cert(node, is_client=is_client)
    assert node_cert_after['type'] != 'generated', \
           'node_cert_after type == generated'
    assert node_cert_after['pem'] == prev_cert_before['pem'], \
           'node_cert_after pem != node_cert_before pem'


def wait_any_node_unhealthy(node, timeout=60):
    # Wait until the cluster reports a node as not healthy, so the CA reset
    # check sees it as unreachable
    def check():
        return testlib.diag_eval(
            node, "length(ns_node_disco:nodes_actual()) "
            "< length(ns_node_disco:nodes_wanted())").text == "true"
    testlib.poll_for_condition(check, sleep_time=0.5, timeout=timeout)


def regenerate_certs(cluster, force_reset_ca=True, drop_uploaded_certs=True):
    params = {'forceResetCACertificate': 'true' if force_reset_ca else 'false',
              'dropUploadedCertificates': 'true' if drop_uploaded_certs
                                                 else 'false'}
    def regen():
        r = testlib.post(cluster, '/controller/regenerateCertificate',
                         params=params)
        # Retry if 503
        assert r.status_code != 503
        return r

    r_final = testlib.poll_for_condition(
        regen,
        sleep_time=0.5,
        timeout=60,
        retry_on_assert=True)

    assert r_final.status_code == 200
    return r_final.text


def get_trusted_CAs(cluster):
    r = testlib.get_succ(cluster, '/pools/default/trustedCAs')
    return r.json()


def get_node_certs(cluster):
    node_certs = []
    for node in cluster.connected_nodes:
        node_cert = get_node_cert(node)
        client_cert = get_node_cert(node, is_client=True)
        node_certs.append((node, node_cert, client_cert))
    return node_certs


def get_node_cert(node, is_client=False):
    if is_client:
        r = testlib.get_succ(node, '/pools/default/certificates/client')
    else:
        r = testlib.get_succ(node, '/pools/default/certificates')
    hostname = node.hostname()
    res = r.json()
    for cert_props in res:
        if cert_props['node'] == hostname:
            return cert_props
    raise Exception(f'No node cert found for {hostname}: {res}')


def load_node_cert(node, cert, key, passphrase=None):
    load_cert(node, cert, key, passphrase, is_client=False)


def load_client_cert(node, cert, key, passphrase=None):
    load_cert(node, cert, key, passphrase, is_client=True)


def generate_and_load_node_cert(node, *args, **kwargs):
    cert, key = generate_node_certs(node.addr(), *args, **kwargs)
    load_node_cert(node, cert, key, passphrase=None)
    return (cert, key)


def generate_and_load_internal_client_cert(node, *args, **kwargs):
    cert, key = generate_internal_client_cert(*args, **kwargs)
    load_client_cert(node, cert, key, passphrase=None)
    return (cert, key)


def load_cert(node, cert, key, passphrase, is_client, force_reload=False,
              expected_error=None):
    inbox_dir = os.path.join(node.data_path(), 'inbox')
    chain_file_name = 'client_chain.pem' if is_client else 'chain.pem'
    chain_path = os.path.join(inbox_dir, chain_file_name)
    pkey_file_name = 'client_pkey.key' if is_client else 'pkey.key'
    pkey_path = os.path.join(inbox_dir, pkey_file_name)
    os.makedirs(inbox_dir, exist_ok=True)
    try:
        with open(chain_path, 'w') as f:
            f.write(cert)
        with open(pkey_path, 'w') as f:
            f.write(key)
        endpoint = 'reloadClientCertificate' if is_client \
                   else 'reloadCertificate'
        data = None
        if passphrase is not None:
            data = {'privateKeyPassphrase': {'type': 'plain',
                                             'password': passphrase}}
        if force_reload:
            if data is None:
                data = {'forceReload': True}
            else:
                data['forceReload'] = True
        if expected_error is None:
            testlib.post_succ(node, f'/node/controller/{endpoint}', json=data)
            r = get_node_cert(node, is_client=is_client)
            assert r['type'] == 'uploaded', f'cert type {r} != uploaded'
            return r
        else:
            r = testlib.post_fail(node, f'/node/controller/{endpoint}',
                                  expected_code=400, json=data)
            assert expected_error in r.text, \
                f'expected error containing "{expected_error}", ' \
                f'got: {r.text}'
            return r
    finally:
        if os.path.exists(chain_path):
            os.remove(chain_path)
        if os.path.exists(pkey_path):
            os.remove(pkey_path)


def load_ca(node, CA):
    ca_dir = os.path.join(node.data_path(), 'inbox', 'CA')
    ca_path = os.path.join(ca_dir, 'ca.pem')
    os.makedirs(ca_dir, exist_ok=True)
    try:
        with open(ca_path, 'w') as f:
            f.write(CA)

        r = testlib.post_succ(node, '/node/controller/loadTrustedCAs')
        r = r.json()
        # Returning a list mostly to handle the case when that certificate
        # is already loaded. In this case we don't need to remove it in
        # teardown()
        return [c['id'] for c in r]
    finally:
        if os.path.exists(ca_path):
            os.remove(ca_path)


def run_generate_cert(args, env):
    r = subprocess.run([testlib.get_utility_path('generate_cert')] + args,
                       capture_output=True, env=env)
    assert r.returncode == 0, f'generate_cert returned {r.returncode}'

    separator = '-----END CERTIFICATE-----'
    tokens = r.stdout.decode().split(separator)
    assert len(tokens) == 2, f'unexpected return of generate_cert: {r.output}'
    cert = tokens[0] + separator
    key = tokens[1]
    print(f'Generated cert: {cert}\nGenerated key: {key}')
    return (cert, key)


def generate_internal_client_cert(CA, CAKey, name_in_cert, extra_args=None):
    return generate_client_cert(CA, CAKey,
                                email=f'{name_in_cert}@internal.couchbase.com',
                                extra_args=extra_args)


def generate_client_cert(CA, CAKey, cn="TEST CLIENT CERT",
                         email='test_client@example.com', extra_args=None):
    args = ['--generate-leaf', '--common-name', cn,
            '--san-emails', email, '--client']
    if extra_args is not None:
        args.extend(extra_args)

    return run_generate_cert(args, {'CACERT': CA, 'CAPKEY': CAKey})


def generate_node_certs(node_addr, CA, CAKey, key_type='rsa',
                        cn_prefix="Couchbase Server", generate_leaf=True,
                        extra_args=None):
    try:
        ipaddress.ip_address(node_addr)
        is_raw = True
    except ValueError:
        is_raw = False

    args = ['--generate-leaf'] if generate_leaf else []
    args.extend(['--common-name', 'TEST Server Node',
                 '--common-name-prefix', cn_prefix,
                 '--san-ip-addrs' if is_raw else '--san-dns-names', node_addr,
                 '--pkey-type', key_type])
    if extra_args is not None:
        args.extend(extra_args)

    return run_generate_cert(args, {'CACERT': CA, 'CAPKEY': CAKey})


def generate_cert_with_eku(node_addr, CA, CAKey, is_client=False,
                           purposes=None, critical=False):
    eku_args = ['--eku-critical'] if critical else []
    if purposes is not None:
        eku_args.extend(['--eku-purposes', ','.join(purposes)])
    if is_client:
        return generate_internal_client_cert(CA, CAKey, 'test_name',
                                             extra_args=eku_args)
    return generate_node_certs(node_addr, CA, CAKey, extra_args=eku_args)


# A BOOLEAN where a SEQUENCE OF OID is expected, so the extension fails to
# decode as ExtKeyUsageSyntax. generate_cert can't emit one, as Go's x509 only
# produces a well formed extended key usage
malformed_eku = x509.UnrecognizedExtension(ExtensionOID.EXTENDED_KEY_USAGE,
                                           b'\x01\x01\xff')

ca_key_usage = x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                             crl_sign=True, content_commitment=False,
                             key_encipherment=False, data_encipherment=False,
                             key_agreement=False, encipher_only=False,
                             decipher_only=False)


def parse_ca(CA, CAKey):
    return (x509.load_pem_x509_certificate(CA.encode()),
            serialization.load_pem_private_key(CAKey.encode(), password=None))


def node_san(node_addr):
    try:
        return x509.IPAddress(ipaddress.ip_address(node_addr))
    except ValueError:
        return x509.DNSName(node_addr)


def cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def key_to_pem(key):
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode()


def sign_cert(common_name, sans, issuer, signer_key, eku=None, is_ca=False):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder() \
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                    common_name)])) \
        .issuer_name(issuer) \
        .public_key(key.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(now - timedelta(days=1)) \
        .not_valid_after(now + timedelta(days=824)) \
        .add_extension(x509.SubjectAlternativeName(sans), critical=False) \
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None),
                       critical=True)
    if is_ca:
        builder = builder.add_extension(ca_key_usage, critical=True)
    if eku is not None:
        builder = builder.add_extension(eku, critical=False)
    return (builder.sign(signer_key, hashes.SHA256()), key)


def generate_cert_with_malformed_eku(node_addr, CA, CAKey, is_client=False):
    ca_cert, ca_key = parse_ca(CA, CAKey)
    if is_client:
        name = 'TEST CLIENT CERT'
        sans = [x509.RFC822Name('test_name@internal.couchbase.com')]
    else:
        name = 'TEST Server Node'
        sans = [node_san(node_addr)]
    cert, key = sign_cert(name, sans, ca_cert.subject, ca_key,
                          eku=malformed_eku)
    return (cert_to_pem(cert), key_to_pem(key))


# The malformed extension goes on the intermediate rather than the leaf, so the
# decode crash happens partway along the chain. The leaf needs no extended key
# usage, as an absent one permits any purpose
def generate_malformed_intermediate_chain(node_addr, CA, CAKey):
    ca_cert, ca_key = parse_ca(CA, CAKey)
    inter, inter_key = sign_cert(
        'TEST Intermediate CA', [x509.DNSName('intermediate.example.com')],
        ca_cert.subject, ca_key, eku=malformed_eku, is_ca=True)
    leaf, key = sign_cert('TEST Server Node', [node_san(node_addr)],
                          inter.subject, inter_key)
    return (cert_to_pem(leaf) + cert_to_pem(inter), key_to_pem(key))


def to_pkcs8(key, passphrase):
    args = ['pkcs8', '-topk8']
    encr_args = ['-v2', 'aes256', '-passout', f'pass:{passphrase}'] \
                if passphrase is not None else ['-nocrypt']
    r = subprocess.run([testlib.get_utility_path('openssl')] + args + encr_args,
                       capture_output=True,
                       input=key.encode("utf-8"))
    assert r.returncode == 0, f'openssl pkcs8 returned {r.returncode}\n' \
                              f'stdout: {r.stdout.decode()}\n' \
                              f'stderr: {r.stderr.decode()}'
    return r.stdout.decode()


def write_pkcs12(cert, key, out_file, passphrase=None):
    s = testlib.random_str(8)
    in_key_path = os.path.join(os.path.dirname(out_file), f"temp_key_{s}.pem")
    in_crt_path = os.path.join(os.path.dirname(out_file), f"temp_cert_{s}.pem")
    try:
        with open(in_key_path, 'w') as f:
            f.write(key)
        with open(in_crt_path, 'w') as f:
            f.write(cert)

        args = ['pkcs12', '-export', '-out', out_file, '-inkey', in_key_path,
                '-in', in_crt_path]

        encr_args = ['-aes128', '-passout', f'pass:{passphrase}'] \
                    if passphrase is not None else \
                    ['-keypbe',  'NONE', '-certpbe', 'NONE', '-nomaciter',
                     '-passout', 'pass:']

        r = subprocess.run([testlib.get_utility_path('openssl')] + args + \
                           encr_args,
                           capture_output=True)
        assert r.returncode == 0, f'openssl pkcs12 returned {r.returncode}\n' \
                                  f'stdout: {r.stdout.decode()}\n' \
                                  f'stderr: {r.stderr.decode()}'
    finally:
        if os.path.exists(in_crt_path):
            os.remove(in_crt_path)
        if os.path.exists(in_key_path):
            os.remove(in_key_path)


def read_cert_file(filename):
    with open(os.path.join(certs_path(), filename), 'r') as f:
        pem = f.read()
    return pem


def certs_path():
    return os.path.join(testlib.get_resources_dir(), 'test_certs')
