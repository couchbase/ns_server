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
