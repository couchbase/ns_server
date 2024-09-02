# @author Couchbase <info@couchbase.com>
# @copyright 2020-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import requests

import testlib
from testlib import Service


class UsersTestSet(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(services=[Service.KV,
                                                     Service.QUERY,
                                                     Service.CBAS],
                                           # i.e. wait for service up
                                           balanced=True)

    def setup(self):
        self.user = testlib.random_str(10)

    def teardown(self):
        pass

    def test_teardown(self):
        testlib.ensure_deleted(
          self.cluster, f'/settings/rbac/users/local/{self.user}')

    def local_user_create_update_delete_test(self):
        user = self.user
        name1 = testlib.random_str(10)
        password1 = testlib.random_str(10)
        assert_wrong_password(self.cluster, user, password1)

        # User creation
        put_user(self.cluster, 'local', user, password=password1,
                 roles='admin', full_name=name1, groups='',
                 validate_user_props=True)
        assert_authn_and_roles(self.cluster, user, password1, ['admin'])

        # Change password
        password2 = testlib.random_str(10)
        change_user_password(self.cluster, user, password1, password2)
        assert_wrong_password(self.cluster, user, password1)
        assert_authn_and_roles(self.cluster, user, password2, ['admin'])

        # Update user
        name2 = testlib.random_str(10)
        put_user(self.cluster, 'local', user, password=None,
                 roles='ro_admin,admin', full_name=name2,
                 validate_user_props=True)
        # Password should still work
        assert_authn_and_roles(self.cluster, user, password2,
                               ['ro_admin', 'admin'])

        # Update password via user update
        password3 = testlib.random_str(10)
        put_user(self.cluster, 'local', user, password=password3,
                 roles='ro_admin,admin', full_name=name2,
                 validate_user_props=True)
        assert_wrong_password(self.cluster, user, password2)
        assert_authn_and_roles(self.cluster, user, password3,
                               ['ro_admin', 'admin'])

        # Delete user
        delete_user(self.cluster, 'local', user)
        assert_wrong_password(self.cluster, user, password3)

    def local_user_lock_unlock_test(self):
        user = self.user
        name = testlib.random_str(10)
        password = testlib.random_str(10)

        # User creation
        put_user(self.cluster, 'local', user, password=password,
                 roles='admin', full_name=name, groups='')
        assert_not_locked(self.cluster, user, password)

        # Start UI session
        session, headers, node = start_ui_session(self.cluster, user, password)

        # Use UI session
        testlib.get_succ(node, '/pools', headers=headers,
                         session=session, auth=None)

        # Test query endpoint
        testlib.get_succ(self.cluster, '/admin/vitals', service=Service.QUERY,
                         expected_code=200, auth=(user, password))

        # Test CBAS endpoint
        testlib.get_succ(self.cluster, '/analytics/admin/active_requests',
                         service=Service.CBAS, expected_code=200,
                         auth=(user, password))

        # Lock user via PATCH
        lock_user(self.cluster, user)
        assert_locked(self.cluster, user, password)

        # UI session terminated with status 401, such that the UI correctly
        # shows as logged out
        testlib.get_fail(node, '/pools', headers=headers,
                         session=session, expected_code=401, auth=None)

        # Query service gives authentication failure error
        testlib.get_fail(self.cluster, '/admin/vitals', service=Service.QUERY,
                         expected_code=401, auth=(user, password))

        # CBAS gives authentication failure error
        testlib.get_fail(self.cluster, '/analytics/admin/active_requests',
                         service=Service.CBAS, expected_code=401,
                         auth=(user, password))

        # Unlock user via PATCH
        unlock_user(self.cluster, user)
        assert_not_locked(self.cluster, user, password)

        # Lock via PUT
        put_user(self.cluster, 'local', user, password=password,
                 roles='admin', full_name=name, groups='', locked="true")
        assert_locked(self.cluster, user, password)

        # Unlock via PUT
        put_user(self.cluster, 'local', user, password=password,
                 roles='admin', full_name=name, groups='', locked="false")
        assert_not_locked(self.cluster, user, password)


def put_user(cluster_or_node, domain, userid, password=None, roles=None,
             full_name=None, groups=None, locked=None, validate_user_props=False):
    data = {}
    if roles is not None:
        data['roles'] = roles
    if password is not None:
        data['password'] = password
    if full_name is not None:
        data['name'] = full_name
    if groups is not None:
        data['groups'] = groups
    if locked is not None:
        data['locked'] = locked
    testlib.put_succ(cluster_or_node,
                     f'/settings/rbac/users/{domain}/{userid}',
                     data=data)
    if validate_user_props:
        r = testlib.get_succ(cluster_or_node,
                             f'/settings/rbac/users/{domain}/{userid}')
        r = r.json()
        testlib.assert_eq(r['id'], userid)
        testlib.assert_eq(r['domain'], domain)
        testlib.assert_eq(r['name'], full_name)
        if roles is None:
            roles_num = 0
        else:
            roles_num = len(roles.split(','))
        testlib.assert_eq(len(r['roles']), roles_num)
        if groups is None or groups == '':
            expected_groups = []
        else:
            expected_groups = [g.strip() for g in groups.split(',')]
        testlib.assert_eq(sorted(r['groups']), sorted(expected_groups))
        assert 'password_change_date' in r, \
               f'password_change_date is missing in user props: {r}'


def delete_user(cluster_or_node, domain, userid):
    testlib.delete_succ(cluster_or_node,
                        f'/settings/rbac/users/{domain}/{userid}')


def change_user_password(cluster_or_node, user, password, new_password):
    testlib.post_succ(cluster_or_node, '/controller/changePassword',
                      data={'password': new_password}, auth=(user, password))


def lock_user(cluster, user):
    testlib.patch_succ(cluster, '/settings/rbac/users/local/' + user,
                       data={"locked": "true"})


def unlock_user(cluster, user):
    testlib.patch_succ(cluster, '/settings/rbac/users/local/' + user,
                       data={"locked": "false"})


def assert_authn_and_roles(cluster_or_node, user, password, expected_roles):
    r = testlib.get_succ(cluster_or_node, '/whoami', auth=(user, password))
    r = r.json()
    got_roles = [r['role'] for r in r['roles']]
    testlib.assert_eq(sorted(got_roles), sorted(expected_roles))


def assert_wrong_password(cluster_or_node, user, password):
    testlib.get_fail(cluster_or_node, '/pools/default', expected_code=401,
                     auth=(user, password))


def assert_locked(cluster, user, password):
    user_info = testlib.get_succ(cluster,
                                 '/settings/rbac/users/local/' + user).json()
    testlib.assert_eq(user_info.get('locked'), True)

    testlib.get_fail(cluster, '/pools/default', expected_code=401,
                     auth=(user, password))


def assert_not_locked(cluster, user, password):
    user_info = testlib.get_succ(cluster,
                                 '/settings/rbac/users/local/' + user).json()
    testlib.assert_eq(user_info.get('locked'), False)

    testlib.get_succ(cluster, '/pools/default',
                     auth=(user, password))


def start_ui_session(cluster, user, password):
    node = cluster.connected_nodes[0]  # Need consistent node for UI
    session = requests.Session()
    headers = {'Host': testlib.random_str(8), 'ns-server-ui': 'yes'}
    testlib.post_succ(node, '/uilogin', headers=headers,
                      session=session, auth=None, expected_code=200,
                      data={'user': user, 'password': password})
    return session, headers, node
