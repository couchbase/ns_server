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


class UsersBackupTests(testlib.BaseTestSet):
    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise")


    def setup(self, cluster):
        self.username = testlib.random_str(16)
        self.username_ext = testlib.random_str(16)
        self.groupname = testlib.random_str(16)
        self.group_description = testlib.random_str(16)
        self.password = testlib.random_str(16)
        put_group(cluster, self.groupname, self.group_description)
        put_user(cluster, self.username, self.password, self.groupname)
        put_user(cluster, self.username_ext, None, self.groupname,
                 domain='external')
        local_users = testlib.get_succ(cluster,
                                       '/settings/rbac/users/local').json()
        self.local_users_count = len(local_users)
        ext_users = testlib.get_succ(cluster,
                                     '/settings/rbac/users/external').json()
        self.external_users_count = len(ext_users)
        groups = testlib.get_succ(cluster, '/settings/rbac/groups').json()
        self.groups_count = len(groups)


    def teardown(self, cluster):
        testlib.ensure_deleted(
          cluster, f'/settings/rbac/users/local/{self.username}')
        testlib.ensure_deleted(
          cluster, f'/settings/rbac/users/external/{self.username_ext}')
        testlib.ensure_deleted(
          cluster, f'/settings/rbac/groups/{self.groupname}')


    def basic_backup_test(self, cluster):
        backup = testlib.get_succ(cluster, '/settings/rbac/backup').json()
        assert 'version' in backup
        assert backup['version'] == '1'
        assert 'admin' in backup
        assert len(backup['users']) == self.local_users_count + \
                                       self.external_users_count
        assert len(backup['groups']) == self.groups_count


    def no_admin_backup_test(self, cluster):
        params = {'exclude': 'admin'}
        backup = testlib.get_succ(cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == self.local_users_count + \
                                      self.external_users_count
        assert len(backup['groups']) == self.groups_count


    def empty_backup_test(self, cluster):
        params = {'exclude': '*'}
        backup = testlib.get_succ(cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == 0
        assert len(backup['groups']) == 0


    def include_exclude_mutually_exclusive_test(self, cluster):
        params = {'exclude': 'user:*:*', 'include': 'admin'}
        res = testlib.get_fail(cluster, '/settings/rbac/backup', 400,
                               params=params).json()
        assert res['errors']['include'] == \
               'include and exclude are mutually exclusive'


    def only_admin_backup_test(self, cluster):
        params = {'include': 'admin'}
        backup = testlib.get_succ(cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' in backup
        assert len(backup['users']) == 0
        assert len(backup['groups']) == 0


    def only_groups_backup_test(self, cluster):
        params = {'exclude': ['user:*:*', 'admin']}
        backup = testlib.get_succ(cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == 0
        assert len(backup['groups']) == self.groups_count


    def only_local_users_backup_test(self, cluster):
        params = {'exclude': ['user:external:*', 'admin', 'group:*']}
        backup = testlib.get_succ(cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == self.local_users_count
        assert len(backup['groups']) == 0
        for u in backup['users']:
            assert u['domain'] == 'local'


    def only_local_users_backup2_test(self, cluster):
        params = {'include': 'user:local:*'}
        backup = testlib.get_succ(cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == self.local_users_count
        assert len(backup['groups']) == 0
        for u in backup['users']:
            assert u['domain'] == 'local'


    def only_specific_user_and_group_backup_test(self, cluster):
        params = {'include': [f'user:local:{self.username}',
                              f'group:{self.groupname}']}
        backup = testlib.get_succ(cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == 1
        assert len(backup['groups']) == 1
        assert backup['users'][0]['id'] == self.username
        assert backup['groups'][0]['name'] == self.groupname


    def restore_users_and_groups_test(self, cluster):
        backup = testlib.get_succ(cluster, '/settings/rbac/backup').json()

        existing_users_count = self.local_users_count + \
                               self.external_users_count
        users_count = len(backup['users'])
        assert users_count == existing_users_count, \
               f'incorrect users count in backup: {users_count}'
        groups_count = len(backup['groups'])
        assert groups_count == self.groups_count, \
               f'incorrect groups count in backup: {users_count}'

        # Changing password for our user, so we can check later that backup
        # restore has not overwritten that user
        new_password = testlib.random_str(16)
        new_group_description = testlib.random_str(16)
        put_user(cluster, self.username, new_password, self.groupname)
        put_group(cluster, self.groupname, new_group_description)
        restore(cluster, backup, can_overwrite=False,
                expected_counters={'usersSkipped': users_count + 1,
                                   'groupsSkipped': groups_count})
                                                 # +1 because we also skip Admin
        check_user_pass(cluster, self.username, new_password)
        check_user_pass_fail(cluster, self.username, self.password)
        check_group_description(cluster, self.groupname, new_group_description)

        # Now trying to restore users again, but now overwriting users
        restore(cluster, backup, can_overwrite=True,
                expected_counters={'usersOverwritten': users_count + 1,
                                   'groupsOverwritten': groups_count})
                                            # +1 because we also overwrite Admin

        # Now new_password should not work, because we have restored old user
        # from the backup
        check_user_pass(cluster, self.username, self.password)
        check_user_pass_fail(cluster, self.username, new_password)
        check_group_description(cluster, self.groupname, self.group_description)

        # Now delete the user and check that it will be recreated
        testlib.delete_succ(cluster,
                            f'/settings/rbac/users/local/{self.username}')
        testlib.delete_succ(cluster,
                            f'/settings/rbac/groups/{self.groupname}')

        restore(cluster, backup, can_overwrite=False,
                expected_counters={'usersCreated': 1,
                                   'usersSkipped': users_count,
                                   'groupsCreated': 1,
                                   'groupsSkipped': groups_count - 1})

        # Now password should work, because the user is restored from backup
        check_user_pass(cluster, self.username, self.password)
        check_group_description(cluster, self.groupname, self.group_description)


def restore(cluster, backup, expected_counters=None, can_overwrite=False):
    can_overwrite_str = 'true' if can_overwrite else 'false'
    res = testlib.put_succ(cluster, '/settings/rbac/backup',
                           data={'backup': json.dumps(backup),
                                 'canOverwrite': can_overwrite_str}).json()

    assert 'stats' in res
    assert 'usersSkipped' in res
    assert 'usersOverwritten' in res
    assert 'groupsSkipped' in res
    assert 'groupsOverwritten' in res
    assert 'usersCreated' in res['stats']
    assert 'usersSkipped' in res['stats']
    assert 'usersOverwritten' in res['stats']
    assert 'groupsCreated' in res['stats']
    assert 'groupsSkipped' in res['stats']
    assert 'groupsOverwritten' in res['stats']

    for k in res['stats']:
        expected = expected_counters[k] if k in expected_counters else 0
        assert res['stats'][k] == expected,\
               f'invalid \'{k}\' counter returned by PUT /backup ('\
               f'got: {res[k]}, expected: {expected})'

    assert res['stats']['usersSkipped'] == len(res['usersSkipped'])
    assert res['stats']['usersOverwritten'] == len(res['usersOverwritten'])
    assert res['stats']['groupsSkipped'] == len(res['groupsSkipped'])
    assert res['stats']['groupsOverwritten'] == len(res['groupsOverwritten'])


def put_user(cluster, username, password, groups, domain='local'):
    data = {'groups': groups}
    if password is not None:
        data['password'] = password
    testlib.put_succ(cluster, f'/settings/rbac/users/{domain}/{username}',
                     data=data)


def put_group(cluster, group, description):
    testlib.put_succ(cluster, f'/settings/rbac/groups/{group}',
                     data={'roles': 'admin', 'description': description})


def check_user_pass(cluster, username, password):
    testlib.get_succ(cluster, '/pools/default', auth=(username, password))


def check_user_pass_fail(cluster, username, password):
    testlib.get_fail(cluster, '/pools/default', 401, auth=(username, password))


def check_group_description(cluster, group, description):
    res = testlib.get_succ(cluster, f'/settings/rbac/groups/{group}').json()
    assert 'description' in res
    got = res['description']
    assert got == description, \
           f'group {group} has unexpected description ' \
           f'(got: {got}, expected: {description})'
