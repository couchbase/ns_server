# @author Couchbase <info@couchbase.com>
# @copyright 2020 Couchbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import testlib
from ldap_test import LdapServer


class LdapTests(testlib.BaseTestSet):
    port = 10389
    admin_dn = 'cn=admin,dc=example,dc=com'
    admin_password = 'pass1'
    user = 'ldap_user'
    user_password = 'test_password_472956922354'
    group = 'test_group'


    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=1)


    def setup(self, cluster):
        user_dn = f'cn={LdapTests.user},ou=users,dc=example,dc=com'
        self.server = LdapServer({
          'port': LdapTests.port,
          'bind_dn': LdapTests.admin_dn,
          'password': LdapTests.admin_password,
          'base': {'objectclass': ['domain'],
                   'dn': 'dc=example,dc=com',
                   'attributes': {'dc': 'example'}},
          'entries': [
            {'objectclass': 'OrganizationalUnit',
             'dn': 'ou=users,dc=example,dc=com',
             'attributes': {'ou': 'users'}},
            {'objectclass': 'person',
             'dn': user_dn,
             'attributes': {'cn': LdapTests.user,
                            'userPassword': LdapTests.user_password}},
            {'objectclass': 'OrganizationalUnit',
             'dn': 'ou=groups,dc=example,dc=com',
             'attributes': {'ou': 'groups'}},
            {'objectclass': 'GroupOfNames',
             'dn': f'cn={LdapTests.group},ou=groups,dc=example,dc=com',
             'attributes': {'cn': LdapTests.group,
                            'member': [user_dn]}}
          ]})
        self.server.start()


    def teardown(self, cluster):
        self.server.stop()


    def basic_set_and_get_test(self, cluster):
        testlib.delete_config_key(cluster, 'ldap_settings')
        actual_defaults = testlib.get_succ(cluster, '/settings/ldap').json()
        expected_defaults = {'authenticationEnabled': False,
                             'authorizationEnabled': False,
                             'hosts': [],
                             'port': 389,
                             'encryption': 'None',
                             'userDNMapping': 'None',
                             'bindDN': '',
                             'bindPass': '',
                             'maxParallelConnections': 100,
                             'maxCacheSize': 10000,
                             'requestTimeout': 5000,
                             'nestedGroupsEnabled': False,
                             'nestedGroupsMaxDepth': 10,
                             'failOnMaxDepth': False,
                             'cacheValueLifetime': 300000,
                             'serverCertValidation': True}
        assert expected_defaults == actual_defaults, \
                f"Default settings are incorrect {actual_defaults}"
        settings = {'authenticationEnabled': 'true',
                    'authorizationEnabled': 'true',
                    'hosts': 'host1,host2',
                    'port': 636,
                    'encryption': 'TLS',
                    'bindDN': 'cn=test',
                    'bindPass': 'pass',
                    'userDNMapping': '{"query":"dc=example??one?(cn=%u)"}',
                    'groupsQuery': 'dc=example??one?(member=%D)'}
        expected = expected_defaults.copy()
        expected.update({'authenticationEnabled': True,
                         'authorizationEnabled': True,
                         'hosts': ['host1', 'host2'],
                         'port': 636,
                         'encryption': 'TLS',
                         'bindDN': 'cn=test',
                         'bindPass': '**********',
                         'userDNMapping': {"query":"dc=example??one?(cn=%u)"},
                         'groupsQuery': 'dc=example??one?(member=%D)'})
        testlib.post_succ(cluster, '/settings/ldap', data=settings)
        actual = testlib.get_succ(cluster, '/settings/ldap').json()
        assert expected == actual, f"Returned settings are incorrect: {actual}"


    def json_set_and_get_test(self, cluster):
        settings = {'authenticationEnabled': True,
                    'authorizationEnabled': True,
                    'hosts': ['host1', 'host2'],
                    'port': 636,
                    'encryption': 'TLS',
                    'bindDN': 'cn=test',
                    'bindPass': 'pass',
                    'userDNMapping': {'query':'dc=example??one?(cn=%u)'},
                    'groupsQuery': 'dc=example??one?(member=%D)',
                    'bindMethod': 'Simple',
                    'maxParallelConnections': 100,
                    'maxCacheSize': 1000,
                    'cacheValueLifetime': 5000,
                    'requestTimeout': 5000,
                    'nestedGroupsEnabled': False,
                    'nestedGroupsMaxDepth': 10,
                    'failOnMaxDepth': True,
                    'serverCertValidation': True}
        expected = settings.copy()
        expected.update({'bindPass': '**********'})
        testlib.post_succ(cluster, '/settings/ldap', json=settings)
        actual = testlib.get_succ(cluster, '/settings/ldap').json()
        assert expected == actual, f"Returned settings are incorrect: {actual}"


    def external_user_test(self, cluster):
        testlib.post_succ(cluster, '/settings/ldap',
                          data={'authenticationEnabled': 'false'})
        testlib.put_succ(cluster, f'/settings/rbac/users/external/{LdapTests.user}',
                         data={'roles': 'admin'})
        testlib.get_fail(cluster, '/whoami', 401,
                         auth=(LdapTests.user, LdapTests.user_password))
        LDAPSettings = {'authenticationEnabled': 'true',
                        'authorizationEnabled': 'false',
                        'hosts': 'localhost',
                        'port': LdapTests.port,
                        'encryption': 'None',
                        'bindDN': LdapTests.admin_dn,
                        'bindPass': LdapTests.admin_password,
                        'userDNMapping': '{"query":"ou=users,dc=example,dc=com??one?(cn=%u)"}'}
        testlib.post_succ(cluster, '/settings/ldap', data=LDAPSettings)
        res = testlib.get_succ(cluster, '/whoami', auth=(LdapTests.user, LdapTests.user_password))
        assert [{'role': 'admin'}] == res.json()['roles']


    def ldap_group_test(self, cluster):
        LDAPSettings = {'authenticationEnabled': 'true',
                        'authorizationEnabled': 'true',
                        'hosts': 'localhost',
                        'port': LdapTests.port,
                        'encryption': 'None',
                        'bindDN': LdapTests.admin_dn,
                        'bindPass': LdapTests.admin_password,
                        'userDNMapping': '{"query":"ou=users,dc=example,dc=com??one?(cn=%u)"}',
                        'groupsQuery': 'ou=groups,dc=example,dc=com??one?(member=%D)'}
        testlib.post_succ(cluster, '/settings/ldap', data=LDAPSettings)
        testlib.ensure_deleted(cluster, f'/settings/rbac/users/external/{LdapTests.user}')
        testlib.ensure_deleted(cluster, f'/settings/rbac/groups/{LdapTests.group}')
        res = testlib.get_succ(cluster, '/whoami', auth=(LdapTests.user, LdapTests.user_password))
        assert [] == res.json()['roles']
        testlib.put_succ(cluster, f'/settings/rbac/groups/{LdapTests.group}',
                         data={'ldap_group_ref':f'cn={LdapTests.group},ou=groups,dc=example,dc=com',
                               'roles': ''})
        res = testlib.get_succ(cluster, '/whoami', auth=(LdapTests.user, LdapTests.user_password))
        assert [] == res.json()['roles']
        testlib.put_succ(cluster, f'/settings/rbac/groups/{LdapTests.group}',
                         data={'ldap_group_ref':f'cn={LdapTests.group},ou=groups,dc=example,dc=com',
                               'roles': 'admin'})
        res = testlib.get_succ(cluster, '/whoami', auth=(LdapTests.user, LdapTests.user_password))
        assert [{'role': 'admin'}] == res.json()['roles']
