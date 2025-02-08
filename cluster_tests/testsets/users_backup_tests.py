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
import os
from testsets.users_tests import put_user, delete_user, lock_user, unlock_user


class UsersBackupTests(testlib.BaseTestSet):
    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise")


    def setup(self):
        self.username = testlib.random_str(16)
        self.username_ext = testlib.random_str(16)
        self.groupname = testlib.random_str(16)
        self.group_description = testlib.random_str(16)
        self.password = testlib.random_str(16)
        put_group(self.cluster, self.groupname, self.group_description)
        put_user(self.cluster, 'local', self.username, password=self.password,
                 groups=self.groupname)
        put_user(self.cluster, 'external', self.username_ext,
                 groups=self.groupname)
        local_users = testlib.get_succ(self.cluster,
                                       '/settings/rbac/users/local').json()
        self.local_users_count = len(local_users)
        ext_users = testlib.get_succ(self.cluster,
                                     '/settings/rbac/users/external').json()
        self.external_users_count = len(ext_users)
        groups = testlib.get_succ(self.cluster, '/settings/rbac/groups').json()
        self.groups_count = len(groups)


    def teardown(self):
        testlib.ensure_deleted(
          self.cluster, f'/settings/rbac/users/local/{self.username}')
        testlib.ensure_deleted(
          self.cluster, f'/settings/rbac/users/external/{self.username_ext}')
        testlib.ensure_deleted(
          self.cluster, f'/settings/rbac/groups/{self.groupname}')


    def basic_backup_test(self):
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup').json()
        assert 'version' in backup
        assert backup['version'] == '1'
        assert 'admin' in backup
        assert len(backup['users']) == self.local_users_count + \
                                       self.external_users_count
        assert len(backup['groups']) == self.groups_count


    def no_admin_backup_test(self):
        params = {'exclude': 'admin'}
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == self.local_users_count + \
                                      self.external_users_count
        assert len(backup['groups']) == self.groups_count


    def empty_backup_test(self):
        params = {'exclude': '*'}
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == 0
        assert len(backup['groups']) == 0


    def include_exclude_mutually_exclusive_test(self):
        params = {'exclude': 'user:*:*', 'include': 'admin'}
        res = testlib.get_fail(self.cluster, '/settings/rbac/backup', 400,
                               params=params).json()
        assert res['errors']['include'] == \
               'include and exclude are mutually exclusive'


    def only_admin_backup_test(self):
        params = {'include': 'admin'}
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' in backup
        assert len(backup['users']) == 0
        assert len(backup['groups']) == 0


    def only_groups_backup_test(self):
        params = {'exclude': ['user:*:*', 'admin']}
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == 0
        assert len(backup['groups']) == self.groups_count


    def only_local_users_backup_test(self):
        params = {'exclude': ['user:external:*', 'admin', 'group:*']}
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == self.local_users_count
        assert len(backup['groups']) == 0
        for u in backup['users']:
            assert u['domain'] == 'local'


    def only_local_users_backup2_test(self):
        params = {'include': 'user:local:*'}
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == self.local_users_count
        assert len(backup['groups']) == 0
        for u in backup['users']:
            assert u['domain'] == 'local'


    def only_specific_user_and_group_backup_test(self):
        params = {'include': [f'user:local:{self.username}',
                              f'group:{self.groupname}']}
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup',
                                  params=params).json()
        assert 'admin' not in backup
        assert len(backup['users']) == 1
        assert len(backup['groups']) == 1
        assert backup['users'][0]['id'] == self.username
        assert backup['groups'][0]['name'] == self.groupname


    def restore_users_and_groups_test(self):
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup').json()

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
        put_user(self.cluster, 'local', self.username, password=new_password,
                 groups=self.groupname)
        put_group(self.cluster, self.groupname, new_group_description)
        restore(self.cluster, backup, can_overwrite=False,
                expected_counters={'usersSkipped': users_count + 1,
                                   'groupsSkipped': groups_count})
                                                 # +1 because we also skip Admin
        check_user_pass(self.cluster, self.username, new_password)
        check_user_pass_fail(self.cluster, self.username, self.password)
        check_group_description(self.cluster, self.groupname,
                                new_group_description)

        # Now trying to restore users again, but now overwriting users
        restore(self.cluster, backup, can_overwrite=True,
                expected_counters={'usersOverwritten': users_count + 1,
                                   'groupsOverwritten': groups_count})
                                            # +1 because we also overwrite Admin

        # Now new_password should not work, because we have restored old user
        # from the backup
        check_user_pass(self.cluster, self.username, self.password)
        check_user_pass_fail(self.cluster, self.username, new_password)
        check_group_description(self.cluster, self.groupname,
                                self.group_description)

        # Lock the user, to check that locked status is correctly restored
        lock_user(self.cluster, self.username)
        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup').json()

        # Now delete the user and check that it will be recreated
        delete_user(self.cluster, 'local', self.username)
        testlib.delete_succ(self.cluster,
                            f'/settings/rbac/groups/{self.groupname}')

        restore(self.cluster, backup, can_overwrite=False,
                expected_counters={'usersCreated': 1,
                                   'usersSkipped': users_count,
                                   'groupsCreated': 1,
                                   'groupsSkipped': groups_count - 1})

        # Password should not yet work, because user is locked
        check_user_pass_fail(self.cluster, self.username, self.password)

        unlock_user(self.cluster, self.username)

        # Now password should work, because the user is restored from backup
        # (and unlocked)
        check_user_pass(self.cluster, self.username, self.password)
        check_group_description(self.cluster, self.groupname,
                                self.group_description)

        # Test user with a temporary password
        put_user(self.cluster, 'local', self.username, password=self.password,
                 temporary_password="true")

        backup = testlib.get_succ(self.cluster, '/settings/rbac/backup').json()

        # Now delete the user and check that it will be recreated
        delete_user(self.cluster, 'local', self.username)

        restore(self.cluster, backup, can_overwrite=False,
                expected_counters={'usersCreated': 1,
                                   'usersSkipped': users_count,
                                   'groupsCreated': 0,
                                   'groupsSkipped': groups_count})

        # Now password should give a 403 error as it is single use
        check_user_pass_fail(self.cluster, self.username, self.password,
                             status=403)


    # Restore a backup taken on a 7.6.x system containing roles that have
    # been replaced with new ones. The restoration should transform the old
    # roles into the new ones.
    def secure_restore_from_older_release_backup_file_test(self):
        # File is a result of /setting/rbac/backup on 7.6.x system.
        backup_file_path = os.path.join(testlib.get_resources_dir(), "fixtures",
                                        "full_backup.json")
        with open(backup_file_path) as f:
            backup = json.load(f)

        try:
            # Create a user with admin role to do the restore. The admin is
            # needed as the backup contains users with security roles. It's
            # some of these security roles whose transformation we're verifying.
            user = 'FullAdmin'
            name = testlib.random_str(10)
            password = testlib.random_str(10)
            put_user(self.cluster, 'local', user, password, roles='admin',
                     full_name=name, groups='', validate_user_props=True)

            restore(self.cluster, backup, can_overwrite=False,
                    expected_counters={'usersCreated': 11,
                                       # Skip 'Administrator'
                                       'usersSkipped': 1,
                                       'groupsCreated': 0,
                                       'groupsSkipped': 0},
                    auth_user=(user, password))

            # Ensure these tranformations have occurred where old roles, no
            # longer supported on morpheus are replaced with supported roles.
            #
            #   localsecurityadmin76:
            #       security_admin_local => security_admin + user_admin_local
            #   externalsecurityadmin76:
            #       security_admin_external => security_admin +
            #                                   user_admin_external
            #   localsecurityandbackupadmin76:
            #       data_backup + local_admin_security =>
            #           data_backup + Local User Admin + Security Admin

            verify_roles(self.cluster, 'localsecurityadmin76',
                         ['security_admin', 'user_admin_local'])
            verify_roles(self.cluster, 'externalsecurityadmin76',
                         ['security_admin', 'user_admin_external'])
            verify_roles(self.cluster, 'localsecurityandbackupadmin76',
                         ['data_backup', 'security_admin', 'user_admin_local'])

            # We now have a mixture of security and non-security roles. Do
            # a backup from a non-security role and ensure none of the security
            # roles get backed up.
            user2 = 'UserAdminLocal'
            name2 = testlib.random_str(10)
            password2 = testlib.random_str(10)
            put_user(self.cluster, 'local', user2, password2,
                     roles='user_admin_local', full_name=name2, groups='',
                     validate_user_props=True)

            kwargs = {"auth": (user2, password2)}
            backup2 = testlib.get_succ(self.cluster, '/settings/rbac/backup',
                                   **kwargs).json()
            users2 = [user["id"] for user in backup2.get("users", [])]

            assert 'localsecurityadmin76' not in users2
            assert 'externalsecurityadmin76' not in users2
            assert 'localsecurityandbackupadmin76' not in users2
            assert 'roadmin76' not in users2
            # User admins cannot CRUD user admins
            assert user2 not in users2

            assert len(users2) == 7

        finally:
            # Cleanup the users created by the restore
            users = [user["id"] for user in backup.get("users", [])]
            for u in users:
                testlib.ensure_deleted(
                    self.cluster, f'/settings/rbac/users/local/{u}')

            # Cleanup the users created by this test
            testlib.ensure_deleted(
                    self.cluster, f'/settings/rbac/users/local/{user}')
            testlib.ensure_deleted(
                    self.cluster, f'/settings/rbac/users/local/{user2}')

    # Restore a backup taken on a 7.6.x system containing roles that
    # are security roles. This is done by a user without a security role
    # and so the result should be that none of the security roles get
    # restored.
    def unsecure_restore_from_older_release_backup_file_test(self):
        # File is a result of /setting/rbac/backup on 7.6.x system.
        backup_file_path = os.path.join(testlib.get_resources_dir(), "fixtures",
                                        "full_backup.json")
        with open(backup_file_path) as f:
            backup = json.load(f)

        try:
            # Create a user with the backup_admin + local_user_admin roles
            user = 'BackupLocalUserAdmin'
            name = testlib.random_str(10)
            password = testlib.random_str(10)
            put_user(self.cluster, 'local', user, password,
                     roles='backup_admin,user_admin_local',
                     full_name=name, groups='', validate_user_props=True)
            restore(self.cluster, backup, can_overwrite=False,
                    expected_counters={'usersCreated': 6,
                                       'usersSkipped': 6,
                                       'groupsCreated': 0,
                                       'groupsSkipped': 0},
                    auth_user=(user, password))

        finally:
            # Cleanup the users created by the restore
            users = [user["id"] for user in backup.get("users", [])]
            for u in users:
                testlib.ensure_deleted(
                        self.cluster, f'/settings/rbac/users/local/{u}')

            # Cleanup the admin created by this test
            testlib.ensure_deleted(
                    self.cluster, f'/settings/rbac/users/local/{user}')


def verify_roles(cluster, username, expected_roles):
    path = f'/settings/rbac/users/local/{username}'
    user_info = testlib.get_succ(cluster, path).json()
    user_roles = [role["role"] for role in user_info.get("roles", [])]

    for r in expected_roles:
        assert r in user_roles, f"Missing {r} in {user_roles}"


def restore(cluster, backup, expected_counters=None, can_overwrite=False,
            auth_user=None):
    can_overwrite_str = 'true' if can_overwrite else 'false'
    kwargs = {"auth": auth_user} if auth_user is not None else {}
    res = testlib.put_succ(cluster, '/settings/rbac/backup',
                           data={'backup': json.dumps(backup),
                                 'canOverwrite': can_overwrite_str},
                           **kwargs).json()

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


def put_group(cluster, group, description):
    testlib.put_succ(cluster, f'/settings/rbac/groups/{group}',
                     data={'roles': 'admin', 'description': description})


def check_user_pass(cluster, username, password):
    testlib.get_succ(cluster, '/pools/default', auth=(username, password))


def check_user_pass_fail(cluster, username, password, status=401):
    testlib.get_fail(cluster, '/pools/default', status,
                     auth=(username, password))


def check_group_description(cluster, group, description):
    res = testlib.get_succ(cluster, f'/settings/rbac/groups/{group}').json()
    assert 'description' in res
    got = res['description']
    assert got == description, \
           f'group {group} has unexpected description ' \
           f'(got: {got}, expected: {description})'
