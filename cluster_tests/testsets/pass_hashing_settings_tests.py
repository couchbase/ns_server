# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import testlib
from testsets.authn_tests import scram_sha_auth


class PassHashingSettingsTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements()

    def setup(self):
        self.username_argon = testlib.random_str(16)
        self.username_pbkdf2 = testlib.random_str(16)
        self.username_sha = testlib.random_str(16)
        self.test_username = testlib.random_str(16)

    def test_teardown(self):
        delete_user(self.cluster, self.test_username)
        update_pwd_hash_migration_setting(self.cluster, "false")

    def teardown(self):
        delete_user(self.cluster, self.username_argon)
        delete_user(self.cluster, self.username_pbkdf2)
        delete_user(self.cluster, self.username_sha)
        testlib.delete_succ(self.cluster, '/settings/security/passwordHashAlg')
        testlib.delete_succ(self.cluster,
                            '/settings/security/scramSha512Enabled')
        testlib.delete_succ(self.cluster,
                            '/settings/security/scramSha256Enabled')
        testlib.delete_succ(self.cluster,
                            '/settings/security/scramSha1Enabled')
        testlib.delete_succ(self.cluster,
                            '/settings/security/scramShaIterations')
        testlib.delete_succ(self.cluster,
                            '/settings/security/argon2idTime')
        testlib.delete_succ(self.cluster,
                            '/settings/security/argon2idMem')
        testlib.delete_succ(self.cluster,
                            '/settings/security/pbkdf2HmacSha512Iterations')
        testlib.delete_succ(self.cluster,
                            '/settings/security/allowHashMigrationDuringAuth')

    def change_admin_pass_respects_hash_alg_test(self):
        admin = testlib.get_succ(self.cluster,
                                 '/settings/web').json()['username']
        assert admin == self.cluster.auth[0], \
            'this test expects that cluster uses administrator auth'
        password = self.cluster.auth[1]

        def test_hash(expected_hash):
            # changing admin password to make sure password hash is updated
            touch_user_password(self.cluster, admin, password)
            backup = get_backup(self.cluster, 'admin')
            verify_hash_type([backup['admin']], admin, expected_hash)

        testlib.delete_succ(self.cluster, '/settings/security/passwordHashAlg')
        test_hash('argon2id')

        testlib.post_succ(self.cluster, '/settings/security/passwordHashAlg',
                          data='pbkdf2-hmac-sha512')
        test_hash('pbkdf2-hmac-sha512')

        testlib.post_succ(self.cluster, '/settings/security/passwordHashAlg',
                          data='SHA-1')
        test_hash('SHA-1')

        testlib.post_succ(self.cluster, '/settings/security/passwordHashAlg',
                          data='argon2id')
        test_hash('argon2id')

    def user_creation_respects_hash_alg_test(self):
        testlib.post_succ(self.cluster, '/settings/security/passwordHashAlg',
                          data='argon2id')
        pass_argon = create_user(self.cluster, self.username_argon)

        testlib.post_succ(self.cluster, '/settings/security/passwordHashAlg',
                          data='pbkdf2-hmac-sha512')
        pass_pbkdf2 = create_user(self.cluster, self.username_pbkdf2)

        # should not be used but we still need to support it for backward
        # compat
        testlib.post_succ(self.cluster, '/settings/security/passwordHashAlg',
                          data='SHA-1')
        pass_sha = create_user(self.cluster, self.username_sha)

        testlib.delete_succ(self.cluster, '/settings/security/passwordHashAlg')

        r = testlib.get_succ(self.cluster, '/settings/security/passwordHashAlg')
        assert r.text == '"argon2id"', 'unexpected default hash type'

        # Use backup to check that correct hash functions are used
        backup = get_backup(self.cluster, 'user:local:*')

        users = backup['users']

        verify_hash_type(users, self.username_argon, 'argon2id')
        verify_hash_type(users, self.username_pbkdf2, 'pbkdf2-hmac-sha512')
        verify_hash_type(users, self.username_sha, 'SHA-1')

        # Users still should be able to authenticate
        testlib.get_succ(self.cluster, '/pools/default',
                         auth=(self.username_argon, pass_argon))
        testlib.get_succ(self.cluster, '/pools/default',
                         auth=(self.username_pbkdf2, pass_pbkdf2))
        testlib.get_succ(self.cluster, '/pools/default',
                         auth=(self.username_sha, pass_sha))

    def change_pass_respects_hash_alg_test(self):
        testlib.post_succ(self.cluster, '/settings/security/passwordHashAlg',
                          data='argon2id')
        password = create_user(self.cluster, self.test_username)
        testlib.post_succ(self.cluster, '/settings/security/passwordHashAlg',
                          data='pbkdf2-hmac-sha512')

        touch_user_password(self.cluster, self.test_username, password)

        backup = get_backup(self.cluster, f'user:local:{self.test_username}')

        verify_hash_type(backup['users'], self.test_username,
                         'pbkdf2-hmac-sha512')

    def scram_sha1_disable_test(self):
        scram_sha_disable_test(self.cluster, self.test_username,
                               '/settings/security/scramSha1Enabled',
                               'SCRAM-SHA-1')

    def scram_sha256_disable_test(self):
        scram_sha_disable_test(self.cluster, self.test_username,
                               '/settings/security/scramSha256Enabled',
                               'SCRAM-SHA-256')

    def scram_sha512_disable_test(self):
        scram_sha_disable_test(self.cluster, self.test_username,
                               '/settings/security/scramSha512Enabled',
                               'SCRAM-SHA-512')

    def scram_sha_iterations_test(self):
        def assert_iterations(expected):
            backup = get_backup(self.cluster,
                                f'user:local:{self.test_username}')
            auth = backup['users'][0]['auth']
            assert expected == auth['scram-sha-512']['iterations']
            assert expected == auth['scram-sha-256']['iterations']
            assert expected == auth['scram-sha-1']['iterations']

        testlib.delete_succ(self.cluster,
                            '/settings/security/scramSha512Enabled')
        testlib.delete_succ(self.cluster,
                            '/settings/security/scramSha256Enabled')
        testlib.delete_succ(self.cluster, '/settings/security/scramSha1Enabled')
        testlib.delete_succ(self.cluster,
                            '/settings/security/scramShaIterations')

        password = create_user(self.cluster, self.test_username)
        assert_iterations(15000)

        iterations = 12345
        testlib.post_succ(self.cluster, '/settings/security/scramShaIterations',
                          data=str(iterations))

        password = create_user(self.cluster, self.test_username)
        assert_iterations(iterations)

        iterations = 1234
        testlib.post_succ(self.cluster, '/settings/security/scramShaIterations',
                          data=str(iterations))
        touch_user_password(self.cluster, self.test_username, password)
        assert_iterations(iterations)

    def pwd_hash_migration_sha1_to_argon2id_pos_test(self):
        pwd_hash_migration_alg_change_test(self.cluster, self.test_username,
                                           "SHA-1", "argon2id", migrate='true')

    def pwd_hash_migration_sha1_to_argon2id_neg_test(self):
        pwd_hash_migration_alg_change_test(self.cluster, self.test_username,
                                           "SHA-1", "argon2id", migrate='false')

    def pwd_hash_migration_sha1_to_pbkdf2_pos_test(self):
        pwd_hash_migration_alg_change_test(self.cluster, self.test_username,
                                           "SHA-1", "pbkdf2-hmac-sha512",
                                           migrate='true')

    def pwd_hash_migration_sha1_to_pbkdf2_neg_test(self):
        pwd_hash_migration_alg_change_test(self.cluster, self.test_username,
                                           "SHA-1", "pbkdf2-hmac-sha512",
                                           migrate='false')

    def pwd_hash_migration_pbkdf2_to_argon2id_pos_test(self):
        pwd_hash_migration_alg_change_test(self.cluster, self.test_username,
                                           "pbkdf2-hmac-sha512", "argon2id",
                                           migrate='true')

    def pwd_hash_migration_pbkdf2_to_argon2id_neg_test(self):
        pwd_hash_migration_alg_change_test(self.cluster, self.test_username,
                                           "pbkdf2-hmac-sha512", "argon2id",
                                           migrate='false')

    def pwd_hash_migration_argon2id_to_pbkdf2_pos_test(self):
        pwd_hash_migration_alg_change_test(self.cluster, self.test_username,
                                           "argon2id", "pbkdf2-hmac-sha512",
                                           migrate='true')

    def pwd_hash_migration_argon2id_to_pbkdf2_neg_test(self):
        pwd_hash_migration_alg_change_test(self.cluster, self.test_username,
                                           "argon2id", "pbkdf2-hmac-sha512",
                                           migrate='false')

    def pwd_hash_migration_change_argon2id_settings_pos_test(self):
        pwd_hash_migration_alg_settings_change_test(
            self.cluster, self.test_username, "argon2id",
            old_settings={"argon2idMem": f"{10 * 1024}", "argon2idTime": "5"},
            new_settings={"argon2idMem": f"{12 * 1024}", "argon2idTime": "7"},
            migrate='true')

    def pwd_hash_migration_change_argon2id_settings_neg_test(self):
        pwd_hash_migration_alg_settings_change_test(
            self.cluster, self.test_username, "argon2id",
            old_settings={"argon2idMem": f"{10 * 1024}", "argon2idTime": "5"},
            new_settings={"argon2idMem": f"{12 * 1024}", "argon2idTime": "7"},
            migrate='false')

    def pwd_hash_migration_change_pbdkf2_settings_pos_test(self):
        pwd_hash_migration_alg_settings_change_test(
            self.cluster, self.test_username, "pbkdf2-hmac-sha512",
            old_settings={"pbkdf2HmacSha512Iterations": "20000"},
            new_settings={"pbkdf2HmacSha512Iterations": "25000"},
            migrate='true')

    def pwd_hash_migration_change_pbdkf2_settings_neg_test(self):
        pwd_hash_migration_alg_settings_change_test(
            self.cluster, self.test_username, "pbkdf2-hmac-sha512",
            old_settings={"pbkdf2HmacSha512Iterations": "20000"},
            new_settings={"pbkdf2HmacSha512Iterations": "25000"},
            migrate='false')


def verify_hash_type(users, username, expected_hash_type):
    record = next(filter(lambda x: x['id'] == username, users))
    hash_type = record['auth']['hash']['algorithm']
    assert hash_type == expected_hash_type


def create_user(cluster, username):
    password = testlib.random_str(16)
    testlib.put_succ(cluster, f'/settings/rbac/users/local/{username}',
                     data={'password': password, 'roles': 'ro_admin'})
    return password


def delete_user(cluster, username):
    testlib.ensure_deleted(cluster, f'/settings/rbac/users/local/{username}')


def get_backup(cluster, what):
    return testlib.get_succ(cluster, '/settings/rbac/backup',
                            params={'include': what}).json()


def scram_sha_disable_test(cluster, user, setting_endpoint, scram_type):
    # By default it is enabled: check that hash is present and user
    # can authenticate
    testlib.delete_succ(cluster, setting_endpoint)

    password = create_user(cluster, user)
    backup = get_backup(cluster, f'user:local:{user}')
    assert scram_type.lower() in backup['users'][0]['auth']
    r = scram_sha_auth(scram_type, '/pools/default', (user, password), cluster)
    testlib.assert_http_code(200, r)

    # Disable scram-sha, and checking that user can't authenticate now
    # even if hash is present, also check that hash disappear after
    # password change
    testlib.post_succ(cluster, setting_endpoint, data='false')

    def assert_scram_auth_is_disabled():
        try:
            scram_sha_auth(scram_type, '/pools/default',
                           (user, password), cluster)
            assert False, 'scram auth is expected to crash'
        except ValueError as e:
            err = str(e)
            assert err.startswith('wrong \'WWW-Authenticate\' value: Basic')

    assert_scram_auth_is_disabled()

    touch_user_password(cluster, user, password)

    assert_scram_auth_is_disabled()

    backup = get_backup(cluster, f'user:local:{user}')
    assert scram_type.lower() not in backup['users'][0]['auth']

    # Enable it explicitly and check that it works again
    testlib.post_succ(cluster, setting_endpoint, data='true')

    touch_user_password(cluster, user, password)

    r = scram_sha_auth(scram_type, '/pools/default', (user, password), cluster)
    testlib.assert_http_code(200, r)


def touch_user_password(cluster, user, password):
    testlib.post_succ(cluster, '/controller/changePassword',
                      auth=(user, password), data={'password': password})


def pwd_hash_migration_alg_change_test(
        cluster, user, old_alg, new_alg, migrate):
    update_pwd_hash_alg_type(cluster, old_alg)
    pwd = create_user(cluster, user)

    update_pwd_hash_migration_setting(cluster, migrate)
    update_pwd_hash_alg_type(cluster, new_alg)

    # Trigger a pwd hash migration via authenticating the user.
    authenticate_user(cluster, user, pwd)
    if migrate == "true":
        validate_pwd_hash_type(cluster, user, new_alg)
        # Once the pwd hash have been migrated check if the user can be
        # authenticated.
        authenticate_user(cluster, user, pwd)
    else:
        validate_pwd_hash_type(cluster, user, old_alg)


def pwd_hash_migration_alg_settings_change_test(
        cluster, user, alg, old_settings, new_settings, migrate):
    update_pwd_hash_settings(cluster, alg, old_settings)
    pwd = create_user(cluster, user)

    update_pwd_hash_migration_setting(cluster, migrate)
    update_pwd_hash_settings(cluster, alg, new_settings)

    # Trigger a pwd hash migration via authenticating the user.
    authenticate_user(cluster, user, pwd)
    if migrate == "true":
        validate_pwd_hash_settings(cluster, user, alg, new_settings)
        # Once the pwd hash have been migrated check if the user can be
        # authenticated.
        authenticate_user(cluster, user, pwd)
    else:
        validate_pwd_hash_settings(cluster, user, alg, old_settings)


def validate_pwd_hash_type(cluster, user, alg):
    backup = get_backup(cluster, f"user:local:{user}")
    verify_hash_type(backup['users'], user, alg)


def update_pwd_hash_alg_type(cluster, alg):
    testlib.post_succ(cluster, '/settings/security/passwordHashAlg',
                      data=alg)


def validate_pwd_hash_settings(cluster, user, alg, expected_settings):
    backup = get_backup(cluster, f"user:local:{user}")
    users = backup['users']

    assert len(users) == 1, "Failed retrieving backup info for user - {user}"

    verify_hash_type(users, user, alg)
    auth_info = users[0]

    if alg == "argon2id":
        validate_pwd_hash_argon2id(auth_info, expected_settings)
    elif alg == "pbkdf2-hmac-sha512":
        validate_pwd_hash_pbkdf2(auth_info, expected_settings)
    else:
        assert False, f"Invalid hash algorithm: {alg}"


def validate_pwd_hash_argon2id(auth_info, expected_settings):
    for setting, val in expected_settings.items():
        if setting == "argon2idTime":
            assert auth_info['auth']['hash']['time'] == int(val)
        elif setting == "argon2idMem":
            assert auth_info['auth']['hash']['memory'] == int(val)
        else:
            assert False, f"Invalid pwd hash setting for argon2id: {setting}"


def validate_pwd_hash_pbkdf2(auth_info, expected_settings):
    for setting, val in expected_settings.items():
        if setting == "pbkdf2HmacSha512Iterations":
            assert auth_info['auth']['hash']['iterations'] == int(val)
        else:
            assert False,  f"Invalid pwd hash setting for pbkdf2: {setting}"


def update_pwd_hash_settings(cluster, alg, settings):
    update_pwd_hash_alg_type(cluster, alg)

    if alg == "argon2id":
        valid_settings = ["argon2idTime", "argon2idMem"]
    elif alg == "pbkdf2-hmac-sha512":
        valid_settings = ["pbkdf2HmacSha512Iterations"]

    for setting, value in settings.items():
        assert setting in valid_settings, \
            f"Invalid pwd hash setting ({setting}) for {alg}"

        testlib.post_succ(
            cluster, f"/settings/security/{setting}", data=value)


def update_pwd_hash_migration_setting(cluster, enable):
    testlib.post_succ(
        cluster, '/settings/security/allowHashMigrationDuringAuth',
        data=enable)


def authenticate_user(cluster, user, pwd):
    testlib.get_succ(cluster, "/whoami", auth=(user, pwd))
