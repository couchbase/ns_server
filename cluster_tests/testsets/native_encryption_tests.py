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
import re
import random
from pathlib import Path
from datetime import datetime, timedelta, timezone
from testsets.secret_management_tests import change_password, post_es_config
from testlib.requirements import Service


class NativeEncryptionTests(testlib.BaseTestSet):
    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(min_num_nodes = 2,
                                           edition='Enterprise',
                                           services=[Service.KV],
                                           balanced=True)

    def setup(self):
        # since master password is per-node, we should use the same node for
        # all HTTP requests in all tests that use node secret management (SM)
        self.sm_node = random.choice(self.cluster.connected_nodes)
        self.bucket_name = testlib.random_str(8)

    def teardown(self):
        pass

    def test_teardown(self):
        self.cluster.delete_bucket(self.bucket_name)
        for s in get_secrets(self.cluster):
            delete_secret(self.cluster, s['id'])
        post_es_config(self.sm_node, {'keyStorageType': 'file',
                                      'keyEncrypted': 'true',
                                      'passwordSource': 'env'})
        change_password(self.sm_node, password='')

    def random_node(self):
        return random.choice(self.cluster.connected_nodes)

    def basic_create_update_delete_test(self):
        data = testlib.random_str(8)
        start_len = len(get_secrets(self.random_node()))

        # Create new secret
        secret_json = auto_generated_secret(name='Test Secret 1')
        secret_id = create_secret(self.random_node(), secret_json)

        # Encrypt data using that secret
        encrypted = encrypt_with_key(self.random_node(),
                                     get_kek_id(self.random_node(), secret_id),
                                     data)

        # Checking secrets GET
        secret = get_secret(self.random_node(), secret_id)
        assert len(get_secrets(self.random_node())) == start_len + 1, \
               f'unexpected length of secrets ({secret_list})'
        assert secret['name'] == 'Test Secret 1', 'unexpected name'
        assert secret['type'] == 'auto-generated-aes-key-256', 'unexpected type'
        verify_kek_files(self.cluster, secret)

        # Trying to update the secret that doesn't exist
        update_secret(self.random_node(), secret_id+1, secret_json,
                      expected_code=404)

        # Trying to change type which is not allowed
        secret_json['type'] = 'awskms-aes-key-256'
        errors = update_secret(self.random_node(), secret_id, secret_json,
                               expected_code=400)
        assert errors['type'] == 'the field can\'t be changed', \
               f'unexpected error: {errors}'

        # Changing secret's name
        secret_json['name'] = 'Test Secret 2'
        secret_json['type'] = 'auto-generated-aes-key-256'
        update_secret(self.random_node(), secret_id, secret_json)
        secret = get_secret(self.random_node(), secret_id)
        assert secret['name'] == 'Test Secret 2', 'unexpected name'
        verify_kek_files(self.cluster, secret)
        check_decrypt(self.random_node(),
                      get_kek_id(self.random_node(), secret_id),
                      encrypted, data)

        # Deleting secret
        delete_secret(self.random_node(), secret_id)
        verify_kek_files(self.cluster, secret, verify_missing=True)

    def bucket_with_encryption_test(self):
        secret1_json = auto_generated_secret(name='Test Secret 1')
        secret2_json = auto_generated_secret(name='Test Secret 2')

        secret1_id = create_secret(self.random_node(), secret1_json)

        # Can't create because the secret does not exist
        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestSecretId': secret1_id + 1}
        resp = self.cluster.create_bucket(bucket_props, expected_code=400)
        errors = resp.json()
        e = errors['encryptionAtRestSecretId']
        assert e == 'encryption secret does not exist', \
               f'unexpected error: {errors}'

        bucket_props['encryptionAtRestSecretId'] = secret1_id
        self.cluster.create_bucket(bucket_props, sync=True)

        kek1_id = get_kek_id(self.random_node(), secret1_id)
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=kek1_id)

        # Can't delete because it is in use
        delete_secret(self.random_node(), secret1_id, expected_code=400)

        # Can't modify because the secret doesn't exist
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestSecretId': secret1_id + 1},
                                   expected_code=400)

        secret2_id = create_secret(self.random_node(), secret2_json)
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestSecretId': secret2_id})

        kek2_id = get_kek_id(self.random_node(), secret2_id)
        # update is asynchronous, so we can't assume the dek gets reencrypted
        # immediately
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=kek2_id)

        # Now it can be deleted
        delete_secret(self.random_node(), secret1_id)
        self.cluster.delete_bucket(self.bucket_name)
        delete_secret(self.random_node(), secret2_id)

    def bucket_without_encryption_test(self):
        secret1_json = auto_generated_secret(name='Test Secret 1')
        secret1_id = create_secret(self.random_node(), secret1_json)
        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestSecretId': -1},
                                   sync=True)
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=0)
        # Can't modify because the secret doesn't exist
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestSecretId': secret1_id + 1},
                                   expected_code=400)
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestSecretId': secret1_id})
        kek1_id = get_kek_id(self.random_node(), secret1_id)
        # update is asynchronous, so we can't assume the dek gets reencrypted
        # immediately
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=kek1_id)
        # Can't delete because it is in use
        delete_secret(self.random_node(), secret1_id, expected_code=400)
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestSecretId': -1})
        # Still can't delete because bucket's deks are still encrypted by
        # secret1
        delete_secret(self.random_node(), secret1_id, expected_code=400)

    def secret_not_allowed_to_encrypt_bucket_test(self):
        secret1_json = auto_generated_secret(usage=['bucket-encryption-wrong'])
        secret1_id = create_secret(self.random_node(), secret1_json)

        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestSecretId': secret1_id}

        # Trying to use a secret that is not allowed to encrypt this bucket
        resp = self.cluster.create_bucket(bucket_props, expected_code=400)
        errors = resp.json()
        e = errors['encryptionAtRestSecretId']
        assert e == 'Encryption secret can\'t encrypt this bucket', \
               f'unexpected error: {errors}'

        secret1_json['usage'].append(f'bucket-encryption-{self.bucket_name}')
        update_secret(self.random_node(), secret1_id, secret1_json)

        # Now the secret should work fine for encryption
        self.cluster.create_bucket(bucket_props)

        secret2_json = auto_generated_secret(usage=['bucket-encryption-wrong'])
        secret2_id = create_secret(self.random_node(), secret2_json)

        # Trying to change encryption secret to the one that can't encrypt
        # this bucket
        bucket_props['encryptionAtRestSecretId'] = secret2_id
        resp = self.cluster.update_bucket(bucket_props, expected_code=400)
        assert resp.text == 'Encryption secret can\'t encrypt this bucket', \
               f'unexpected error: {errors}'

        # Trying to forbid using this secret for our bucket encryption
        del secret1_json['usage'][1]
        errors = update_secret(self.random_node(), secret1_id, secret1_json,
                               expected_code=400)
        assert errors['_'] == 'can\'t modify usage as this secret is in use', \
               f'unexpected error: {errors}'

        # Trying again, but now we add permission to encrypt all buckets
        secret1_json['usage'].append('bucket-encryption-*')
        update_secret(self.random_node(), secret1_id, secret1_json)


    def change_SM_password_test(self):
        data = testlib.random_str(8)
        secret_id = create_secret(self.sm_node, auto_generated_secret())
        encrypted = encrypt_with_key(self.sm_node,
                                     get_kek_id(self.sm_node, secret_id),
                                     data)
        change_password(self.sm_node)
        check_decrypt(self.sm_node,
                      get_kek_id(self.sm_node, secret_id), encrypted, data)

    def SM_data_key_rotation_test(self):
        data = testlib.random_str(8)
        secret_id = create_secret(self.sm_node, auto_generated_secret())
        kek_id = get_kek_id(self.sm_node, secret_id)
        encrypted = encrypt_with_key(self.sm_node, kek_id, data)
        testlib.post_succ(self.sm_node, '/node/controller/rotateDataKey')
        check_decrypt(self.sm_node, kek_id, encrypted, data)
        # Run another rotation in order to make sure that the backup key is
        # removed and try decryption again
        testlib.poll_for_condition(
            lambda: testlib.post_succ(self.sm_node,
                                      '/node/controller/rotateDataKey'),
            sleep_time=0.2, attempts=50, retry_on_assert=True, verbose=True)
        check_decrypt(self.sm_node, kek_id, encrypted, data)

    def change_SM_config_test(self):
        data = testlib.random_str(8)
        # Creating a secret that will be encrypted by node SM
        secret1_id = create_secret(self.sm_node, auto_generated_secret())
        encrypted = encrypt_with_key(self.sm_node,
                                     get_kek_id(self.sm_node, secret1_id),
                                     data)

        # Changing configuration of node Secret Manager (it doesn't matter what
        # is changed here, the point is to initiate gosecret config reload)
        post_es_config(self.sm_node, {'keyStorageType': 'file',
                                      'keyEncrypted': 'false'})

        # Check that we can still use already existing secret
        check_decrypt(self.sm_node,
                      get_kek_id(self.sm_node, secret1_id), encrypted, data)

        # Check that we can create new secrets after SM config change
        # and keks are actually saved on disk
        secret2_id = create_secret(self.sm_node, auto_generated_secret())
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret2_id),
                         verify_encryption_kek='encryptionService')

        # Make sure we can create encrypted bucket, and its deks are actually
        # saved on disk
        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestSecretId': secret2_id},
                                   sync=True)

        kek_id = get_kek_id(self.random_node(), secret2_id)
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=kek_id)

    def keks_encrypted_by_keks_test(self):
        data = testlib.random_str(8)
        # Creating the following hierarchy:
        #               key1
        #               /  \
        #            key2  key3
        #             |     |
        #            key4  key5
        secret1_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Root (key1)'))
        secret2_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Level 2 (key2)',
                                             encrypt_by='clusterSecret',
                                             encrypt_secret_id=secret1_id))
        secret3_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Level 2 (key3)',
                                             encrypt_by='clusterSecret',
                                             encrypt_secret_id=secret1_id))
        secret4_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Level 3 (key4)',
                                             encrypt_by='clusterSecret',
                                             encrypt_secret_id=secret2_id))
        secret5_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Level 3 (key5)',
                                             encrypt_by='clusterSecret',
                                             encrypt_secret_id=secret3_id))

        # Can't create secret because encryption key with such id doesn't exist
        create_secret(self.random_node(),
                      auto_generated_secret(name='key6',
                                            encrypt_by='clusterSecret',
                                            encrypt_secret_id=secret5_id + 1),
                      expected_code=400)

        # Testing that keys on disk are encrypted by correct keks

        # Root:
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret1_id),
                         verify_encryption_kek='encryptionService')
        # Level 2:
        kek1_id = get_kek_id(self.random_node(), secret1_id)
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret2_id),
                         verify_encryption_kek=kek1_id)
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret3_id),
                         verify_encryption_kek=kek1_id)

        # Level 3:
        kek2_id = get_kek_id(self.random_node(), secret2_id)
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret4_id),
                         verify_encryption_kek=kek2_id)

        kek3_id = get_kek_id(self.random_node(), secret3_id)
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret5_id),
                         verify_encryption_kek=kek3_id)

        # Testing that we can use keys from lowest level for encryption and
        # decryption.
        encrypted = encrypt_with_key(self.random_node(),
                                     get_kek_id(self.random_node(), secret4_id),
                                     data)
        check_decrypt(self.random_node(),
                      get_kek_id(self.random_node(), secret4_id),
                      encrypted, data)
        encrypted = encrypt_with_key(self.random_node(),
                                     get_kek_id(self.random_node(), secret5_id),
                                     data)
        check_decrypt(self.random_node(),
                      get_kek_id(self.random_node(), secret5_id),
                      encrypted, data)

    def kek_not_allowed_to_encrypt_kek_test(self):
        good_secret_id = create_secret(
                           self.random_node(),
                           auto_generated_secret(name='Good Secret',
                                                 usage=['bucket-encryption-*',
                                                        'secrets-encryption']))
        bad_secret_id = create_secret(
                          self.random_node(),
                          auto_generated_secret(name='Bad Secret',
                                                usage=['bucket-encryption-*']))

        secret = auto_generated_secret(name='Lever 2 (key1)',
                                       encrypt_by='clusterSecret',
                                       encrypt_secret_id=bad_secret_id)

        errors = create_secret(self.random_node(), secret, expected_code=400)
        assert errors['_'] == 'encryption secret not allowed', \
               f'unexpected error: {errors}'

        secret['data']['encryptSecretId'] = good_secret_id
        secret_id = create_secret(self.random_node(), secret)

        secret['data']['encryptSecretId'] = bad_secret_id
        errors = update_secret(self.random_node(), secret_id, secret,
                               expected_code=400)
        assert errors['_'] == 'encryption secret not allowed', \
               f'unexpected error: {errors}'

    def change_encrypt_id_for_kek_test(self):
        secret1_id = create_secret(self.random_node(),
                                   auto_generated_secret(name='Root 1'))
        secret2_id = create_secret(self.random_node(),
                                   auto_generated_secret(name='Root 2'))
        secret3 = auto_generated_secret(name='Lever 2 (key1)',
                                        encrypt_by='clusterSecret',
                                        encrypt_secret_id=secret1_id)
        secret3_id = create_secret(self.random_node(), secret3)

        kek1_id = get_kek_id(self.random_node(), secret1_id)
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret3_id),
                         verify_encryption_kek=kek1_id)

        # Try encrypting secret3 with another secret
        secret3['data']['encryptSecretId'] = secret2_id
        update_secret(self.random_node(), secret3_id, secret3)
        kek2_id = get_kek_id(self.random_node(), secret2_id)
        poll_verify_kek_files(self.cluster,
                              get_secret(self.random_node(), secret3_id),
                              verify_encryption_kek=kek2_id)

        # Try encrypt secret3 with node secret manager
        del secret3['data']['encryptSecretId']
        secret3['data']['encryptBy'] = 'nodeSecretManager'
        update_secret(self.random_node(), secret3_id, secret3)
        poll_verify_kek_files(self.cluster,
                              get_secret(self.random_node(), secret3_id),
                              verify_encryption_kek='encryptionService')

        # Try encrypting secret3 with secret1 again
        secret3['data']['encryptSecretId'] = secret1_id
        secret3['data']['encryptBy'] = 'clusterSecret'
        update_secret(self.random_node(), secret3_id, secret3)
        kek1_id = get_kek_id(self.random_node(), secret1_id)
        poll_verify_kek_files(self.cluster,
                              get_secret(self.random_node(), secret3_id),
                              verify_encryption_kek=kek1_id)

        # Try encrypting secret with itself (must fail)
        secret3['data']['encryptSecretId'] = secret3_id
        update_secret(self.random_node(), secret3_id, secret3,
                      expected_code=400)

    def change_secret_usage_test(self):
        secret1 = auto_generated_secret(usage=['secrets-encryption'])
        secret1_id = create_secret(self.random_node(), secret1)

        secret2 = auto_generated_secret(encrypt_by='clusterSecret',
                                        encrypt_secret_id=secret1_id)
        secret2_id = create_secret(self.random_node(), secret2)

        # Can't remove 'secrets-encryption' usage because this secret is
        # currently encrypting another secret
        secret1['usage'] = ['bucket-encryption-*']
        errors = update_secret(self.random_node(), secret1_id, secret1,
                               expected_code=400)
        assert errors['_'] == 'can\'t modify usage as this secret is in use', \
               f'unexpected error: {errors}'

        # Stop using secret1 for encryption
        del secret2['data']['encryptSecretId']
        secret2['data']['encryptBy'] = 'nodeSecretManager'
        update_secret(self.random_node(), secret2_id, secret2)

        # Now this secret doesn't encrypt anything and usage can be changed
        update_secret(self.random_node(), secret1_id, secret1)

    def rotate_kek_that_encrypts_kek_test(self):
        secret1_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Root'))
        secret2_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Lever 2 (key1)',
                                             encrypt_by='clusterSecret',
                                             encrypt_secret_id=secret1_id))
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret1_id),
                         verify_encryption_kek='encryptionService')

        old_kek_id = get_kek_id(self.random_node(), secret1_id)
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret2_id),
                         verify_encryption_kek=old_kek_id)

        rotate_secret(self.random_node(), secret1_id)

        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret1_id),
                         verify_encryption_kek='encryptionService',
                         verify_key_count=2)

        # the key should change after rotation
        new_kek_id = get_kek_id(self.random_node(), secret1_id)
        assert new_kek_id != old_kek_id, 'kek id hasn\'t changed'

        # all the keys that are encrypted by the key that has been rotated
        # should be reencrypted
        poll_verify_kek_files(self.cluster,
                              get_secret(self.random_node(), secret2_id),
                              verify_encryption_kek=new_kek_id)

    def rotate_kek_that_encrypts_bucket_dek_test(self):
        secret1_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Root'))

        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestSecretId': secret1_id},
                                   sync=True)

        old_kek_id = get_kek_id(self.random_node(), secret1_id)
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=old_kek_id)

        rotate_secret(self.random_node(), secret1_id)

        # the key should change after rotation
        new_kek_id = get_kek_id(self.random_node(), secret1_id)
        assert new_kek_id != old_kek_id, 'kek id hasn\'t changed'

        # all the keys that are encrypted by the key that has been rotated
        # should be reencrypted
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=new_kek_id)


    def auto_rotate_kek_test(self):
        moment = timedelta(seconds=2)
        def now(offset):
            tz = timezone(timedelta(hours=offset))
            return datetime.now(tz=tz).replace(microsecond=0)
        bad_next_rotation = (now(7) - moment).isoformat()
        secret = auto_generated_secret(auto_rotation=True,
                                       next_rotation_time=bad_next_rotation)
        errors = create_secret(self.random_node(), secret, expected_code=400)
        assert errors['data']['nextRotationTime'] == 'must be in the future', \
               f'unexpected error: {errors}'

        next_rotation = (now(-7) + moment).isoformat()
        secret = auto_generated_secret(auto_rotation=True,
                                       next_rotation_time=next_rotation)
        secret_id = create_secret(self.random_node(), secret)

        def rotation_happened(key_num, expected_rotation_time_iso):
            s = get_secret(self.random_node(), secret_id)
            if len(s['data']['keys']) < key_num:
                return False
            assert 'lastRotationTime' in s['data'], f'no lastRotationTime: {s}'
            rotation_time_iso = s['data']['lastRotationTime']
            rotation_time = datetime.fromisoformat(rotation_time_iso)
            expected_time = datetime.fromisoformat(expected_rotation_time_iso)
            assert rotation_time >= expected_time, \
                   f'rotation happened too early'
            assert (rotation_time - expected_time).seconds <= 10, \
                   f'rotation happend too late'
            return True

        testlib.poll_for_condition(
            lambda: rotation_happened(2, next_rotation),
            sleep_time=0.3, timeout=10)

        # Trying to update secret with new rotation date and check that rotation
        # happens again. Timezone is random. It should not change anything.
        next_rotation = (now(11) + moment).isoformat()
        secret['data']['nextRotationTime'] = next_rotation
        update_secret(self.random_node(), secret_id, secret)

        # Making sure update doesn't overwrite lastRotationTime
        s = get_secret(self.random_node(), secret_id)
        assert 'lastRotationTime' in s['data'], f'no lastRotationTime: {s}'

        testlib.poll_for_condition(
            lambda: rotation_happened(3, next_rotation),
            sleep_time=0.3, timeout=10)


def auto_generated_secret(name=None,
                          usage=None,
                          auto_rotation=False, rotation_interval=7,
                          next_rotation_time=None,
                          encrypt_by='nodeSecretManager',
                          encrypt_secret_id=None):
    if usage is None:
        usage = ['bucket-encryption-*', 'secrets-encryption']
    if name is None:
        name = f'Test secret {testlib.random_str(5)}'
    optional = {}
    if encrypt_secret_id is not None:
        optional['encryptSecretId'] = encrypt_secret_id
    if next_rotation_time is not None:
        optional['nextRotationTime'] = next_rotation_time
    return {'name': name,
            'type': 'auto-generated-aes-key-256',
            'usage': usage,
            'data': {'autoRotation': auto_rotation,
                     'rotationIntervalInDays': rotation_interval,
                     'encryptBy': encrypt_by, **optional}}


def get_secret(cluster, secret_id):
    return testlib.get_succ(cluster, f'/settings/secrets/{secret_id}').json()


def get_secrets(cluster):
    return testlib.get_succ(cluster, '/settings/secrets').json()


def create_secret(cluster, json, expected_code=200):
    r = testlib.post_succ(cluster, '/settings/secrets', json=json,
                          expected_code=expected_code)
    r = r.json()
    if expected_code == 200:
        return r['id']
    else:
        return r['errors']


def update_secret(cluster, secret_id, json, expected_code=200):
    r = testlib.put_succ(cluster, f'/settings/secrets/{secret_id}', json=json,
                         expected_code=expected_code)
    if expected_code == 200:
        r = r.json()
        return r['id']
    elif expected_code == 404:
        return r.text
    else:
        r = r.json()
        return r['errors']


def delete_secret(cluster, secret_id, expected_code=200):
    testlib.delete(cluster, f'/settings/secrets/{secret_id}',
                   expected_code=expected_code)


def verify_kek_files(cluster, secret, verify_key_count=1, **kwargs):
    for node in cluster.connected_nodes:
        if secret['type'] == 'auto-generated-aes-key-256':
            if verify_key_count is not None:
                count = len(secret['data']['keys'])
                assert count == verify_key_count, \
                       f'kek count is unexpected: {count} ' \
                       f'(expected: {verify_key_count})'
            for key in secret['data']['keys']:
                path = Path(node.data_path()) / 'config' / 'keks' / key['id']
                verify_key_file(path, **kwargs)


def poll_verify_kek_files(*args, **kwargs):
    testlib.poll_for_condition(
      lambda: verify_kek_files(*args, **kwargs),
      sleep_time=0.2, attempts=50, retry_on_assert=True, verbose=True)


def verify_bucket_deks_files(cluster, bucket, verify_key_count=1,
                             **kwargs):
    for node in cluster.connected_nodes:
        deks_path = Path(node.data_path()) / 'data' / bucket / 'deks'
        print(f'Checking deks in {deks_path}...')
        if not deks_path.exists():
            if verify_key_count == 0:
                return
            else:
                assert False, f'directory {deks_path} doesn\'t exist'
        c = 0
        for path in deks_path.iterdir():
            if path.name != 'active_key':
                c += 1
                verify_key_file(path, **kwargs)

        if verify_key_count is not None:
            assert c == verify_key_count, f'dek count is unexpected: {c} ' \
                                          f'(expected: {verify_key_count})'


def poll_verify_bucket_deks_files(*args, **kwargs):
    testlib.poll_for_condition(
      lambda: verify_bucket_deks_files(*args, **kwargs),
      sleep_time=0.2, attempts=50, retry_on_assert=True, verbose=True)


def verify_key_file(path, verify_missing=False, verify_encryption_kek=None):
    if verify_missing:
        assert not path.is_file(), f'key file exists: {path}'
    else:
        assert path.is_file(), f'key file doesn\'t exist: {path}'
        content = json.loads(path.read_bytes())
        if verify_encryption_kek is not None:
            has_kek = content['keyData']['encryptionKeyName']
            assert has_kek == verify_encryption_kek, \
                   f'key is encrypted by wrong kek {has_kek} ' \
                   f'(expected: {verify_encryption_kek})'
        assert content['type'] == 'raw-aes-gcm'


def get_kek_id(cluster, secret_id):
    r = get_secret(cluster, secret_id)
    if r['type'] == 'auto-generated-aes-key-256':
        for k in r['data']['keys']:
            if k['active']:
                return k['id']
    return None


def encrypt_with_key(cluster, kek_id, string):
    res = testlib.diag_eval(
            cluster,
            '{ok, B} = ' f'encryption_service:encrypt_key(<<"{string}">>, '
                                                        f'<<"{kek_id}">>),'
            'R = base64:encode_to_string(B),'
            '"Success:" ++ R.')
    search_res = re.search('"Success:(.*)"', res.text)
    assert search_res is not None, f'unexpected decrypt result: {res.text}'
    return search_res.group(1)


def check_decrypt(cluster, kek_id, encrypted_data, expected_data):
    decrypted_data = decrypt_with_key(cluster, kek_id, encrypted_data)
    assert decrypted_data == expected_data, \
           'decrypted data doesn\'t match the original. ' \
           f'Expected: {expected_data}, Got: {decrypted_data}'


def decrypt_with_key(cluster, kek_id, b64data):
    res = testlib.diag_eval(
            cluster,
            f'B = base64:decode("{b64data}"),'
            '{ok, R} = ' f'encryption_service:decrypt_key(B, <<"{kek_id}">>),'
            '"Success:" ++ binary_to_list(R).')
    search_res = re.search('"Success:(.*)"', res.text)
    assert search_res is not None, f'unexpected decrypt result: {res.text}'
    return search_res.group(1)


def rotate_secret(cluster, secret_id):
    testlib.post_succ(cluster, f'/controller/rotateSecret/{secret_id}')
