# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import testlib
import json

SECURITY_SETTINGS_AUDIT_ID = 8237


def _audited_azure_domains(event):
    return 'azure_allowed_domains' in event.get('settings', {})


class WebSettingsTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise")

    def setup(self):
        pass

    def teardown(self):
        self.delete_security_settings('/settings/security')
        self.delete_security_settings('/settings/security/clusterManager')
        pass

    def basic_security_settings_api_test(self):
        path = '/settings/security'
        self.set_and_verify_security_settings_all_at_once(path)
        self.set_and_verify_security_settings_one_by_one(path)
        self.delete_security_settings(path)
        r = testlib.get_succ(self.cluster, path).json()
        testlib.assert_eq(True, r['honorCipherOrder'])
        testlib.assert_eq('tlsv1.2', r['tlsMinVersion'])
        testlib.assert_eq([], r['cipherSuites'])

    # set and delete all at once
    def basic_security_settings_api_cluster_manager_1_test(self):
        path = '/settings/security/clusterManager'
        self.set_and_verify_security_settings_all_at_once(path)
        testlib.delete_succ(self.cluster, path)
        r = testlib.get_succ(self.cluster, path).json()
        testlib.assert_not_in('honorCipherOrder', r)
        testlib.assert_not_in('tlsMinVersion', r)
        testlib.assert_not_in('cipherSuites', r)

    # set and delete one by one
    def basic_security_settings_api_cluster_manager_2_test(self):
        path = '/settings/security/clusterManager'
        self.set_and_verify_security_settings_one_by_one(path)
        self.delete_security_settings(path)
        r = testlib.get_succ(self.cluster, path).json()
        testlib.assert_not_in('honorCipherOrder', r)
        testlib.assert_not_in('tlsMinVersion', r)
        testlib.assert_not_in('cipherSuites', r)

    def set_and_verify_security_settings_all_at_once(
            self, base_endpoint,
            honor_order = False,
            min_vsn = 'tlsv1.3',
            ciphers = ["TLS_AES_128_GCM_SHA256",
                       "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"]):
        testlib.post_succ(self.cluster, base_endpoint,
                          data = {'cipherSuites': json.dumps(ciphers),
                                  'honorCipherOrder': 'true' if honor_order
                                                       else 'false',
                                  'tlsMinVersion': min_vsn})
        self.verify_security_settings(base_endpoint, honor_order, min_vsn,
                                      ciphers)

    def set_and_verify_security_settings_one_by_one(
            self, base_endpoint,
            honor_order = False,
            min_vsn = 'tlsv1.3',
            ciphers = ["TLS_AES_128_GCM_SHA256", \
                       "TLS_ECDHE_ECDSA_WITH_AES_128_CCM"]):
        testlib.post_succ(self.cluster, f'{base_endpoint}/cipherSuites',
                          data = json.dumps(ciphers))
        testlib.post_succ(self.cluster, f'{base_endpoint}/honorCipherOrder',
                          data = 'true' if honor_order else 'false')
        testlib.post_succ(self.cluster, f'{base_endpoint}/tlsMinVersion',
                          data = min_vsn)
        self.verify_security_settings(base_endpoint, honor_order, min_vsn,
                                      ciphers)

    def verify_security_settings(self, base_endpoint, honor_order, min_vsn,
                                 ciphers):
        r = testlib.get_succ(self.cluster, base_endpoint).json()
        testlib.assert_eq(honor_order, r['honorCipherOrder'])
        testlib.assert_eq(min_vsn, r['tlsMinVersion'])
        testlib.assert_eq(ciphers, r['cipherSuites'])
        r = testlib.get_succ(self.cluster,
                             f'{base_endpoint}/honorCipherOrder').json()
        testlib.assert_eq(honor_order, r)
        r = testlib.get_succ(self.cluster,
                             f'{base_endpoint}/tlsMinVersion').json()
        testlib.assert_eq(min_vsn, r)
        r = testlib.get_succ(self.cluster,
                             f'{base_endpoint}/cipherSuites').json()
        testlib.assert_eq(ciphers, r)

    def azure_allowed_domains_test(self):
        path = '/settings/security/azureAllowedDomains'
        node = self.cluster.connected_nodes[0]
        r = testlib.get_succ(node, path).json()
        assert isinstance(r, list), \
            f"Expected a list, got {type(r)}"
        for domain in r:
            assert isinstance(domain, str), \
                f"Expected string, got {type(domain)}"

        default = r
        # Only ever add a domain, as removing one that an existing secret uses
        # is rejected
        domains = default + ['vault.example.com']
        auditing_enabled = False
        try:
            testlib.set_auditd_enabled(self.cluster, True)
            auditing_enabled = True

            # A valid list is stored, and is audited as a list of domains,
            # rather than as all of them concatenated into one string
            offset = testlib.audit_log_offset(node)
            testlib.post_succ(node, path, data=json.dumps(domains))
            testlib.assert_eq(testlib.get_succ(node, path).json(), domains)
            evt = testlib.wait_for_audit_event(
                node, SECURITY_SETTINGS_AUDIT_ID,
                predicate=_audited_azure_domains, since_offset=offset)
            testlib.assert_eq(evt['settings']['azure_allowed_domains'],
                              domains, name='audited domains')

            # Anything but a list of strings is rejected, and, as it is never
            # stored, the setting keeps its old value and nothing is audited.
            # The check above proves that auditing is live by this point.
            offset = testlib.audit_log_offset(node)
            bad_format = ['azureAllowedDomains - Invalid format. '
                          'Expecting a list of strings']
            for body in ['[123, 456]',
                         '["vault.azure.net", 456]',
                         '[["vault.azure.net"]]',
                         'null',
                         '{"a": "b"}']:
                r = testlib.post_fail(node, path, 400, data=body)
                testlib.assert_eq(r.json()['errors'], bad_format,
                                  name=f'errors for {body}')
                testlib.assert_eq(testlib.get_succ(node, path).json(), domains,
                                  name=f'domains after posting {body}')
            r = testlib.post_fail(node, path, 400, data='vault.azure.net')
            testlib.assert_eq(r.json()['errors'],
                              ['azureAllowedDomains - Invalid format. '
                               'Expecting JSON list'])
            testlib.assert_no_audit_event(node, SECURITY_SETTINGS_AUDIT_ID,
                                          predicate=_audited_azure_domains,
                                          since_offset=offset)

            # The old value has to be jsonified as well, for the event log, so
            # a second valid post must succeed too
            testlib.post_succ(node, path, data=json.dumps(default))
            testlib.assert_eq(testlib.get_succ(node, path).json(), default)
        finally:
            testlib.post_succ(node, path, data=json.dumps(default))
            if auditing_enabled:
                testlib.set_auditd_enabled(self.cluster, False)

    def delete_security_settings(self, base_endpoint):
        testlib.delete_succ(self.cluster, f'{base_endpoint}/tlsMinVersion')
        testlib.delete_succ(self.cluster, f'{base_endpoint}/honorCipherOrder')
        testlib.delete_succ(self.cluster, f'{base_endpoint}/cipherSuites')
