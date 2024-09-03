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
import os
import sys
import subprocess
import base64
from pathlib import Path
from datetime import datetime, timedelta, timezone
import dateutil
from testsets.secret_management_tests import change_password, post_es_config
from testlib.requirements import Service
import time
import uuid
from testsets.users_tests import put_user


class NativeEncryptionTests(testlib.BaseTestSet):
    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes = 3,
                                           edition='Enterprise',
                                           services={'n0': [Service.KV],
                                                     'n1': [Service.QUERY],
                                                     'n2': [Service.KV]},
                                           balanced=True)

    def setup(self):
        # since master password is per-node, we should use the same node for
        # all HTTP requests in all tests that use node secret management (SM)
        self.sm_node = random.choice(self.cluster.connected_nodes)
        self.bucket_name = testlib.random_str(8)
        set_cfg_encryption(self.cluster, 'encryption_service', -1)
        # Creating a few keys whose role is to just exist while other tests
        # are running. It increases code coverage.
        id1 = create_secret(self.random_node(), aws_test_secret())
        id2 = create_secret(self.random_node(),
                            auto_generated_secret(encrypt_by='clusterSecret',
                                                  encrypt_secret_id=id1))
        self.pre_created_ids = [id2, id1] # so we can remove them later
        # Memorize all existing ids so we don't remove them in test_teardown
        self.pre_existing_ids = [s['id'] for s in get_secrets(self.cluster)]

    def teardown(self):
        new_existing_ids = [s['id'] for s in get_secrets(self.cluster)]
        for s_id in self.pre_existing_ids:
            assert s_id in new_existing_ids, \
                   f'Secret {s_id} disappeared during tests'
        for s_id in self.pre_created_ids:
            delete_secret(self.cluster, s_id)
        set_cfg_encryption(self.cluster, 'disabled', -1)

    def test_teardown(self):
        set_cfg_encryption(self.cluster, 'encryption_service', -1)
        self.cluster.delete_bucket(self.bucket_name)
        for s in get_secrets(self.cluster):
            if s['id'] not in self.pre_existing_ids:
                delete_secret(self.cluster, s['id'])
        post_es_config(self.sm_node, {'keyStorageType': 'file',
                                      'keyEncrypted': 'true',
                                      'passwordSource': 'env'})
        change_password(self.sm_node, password='')
        set_cfg_dek_limit(self.cluster, None)
        set_bucket_dek_limit(self.cluster, self.bucket_name, None)

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
        e = errors['errors']['encryptionAtRestSecretId']
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

    def secret_not_allowed_to_encrypt_bucket_test(self):
        secret1_json = auto_generated_secret(usage=['bucket-encryption-wrong'])
        secret1_id = create_secret(self.random_node(), secret1_json)

        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestSecretId': secret1_id}

        # Trying to use a secret that is not allowed to encrypt this bucket
        resp = self.cluster.create_bucket(bucket_props, expected_code=400)
        errors = resp.json()
        e = errors['errors']['encryptionAtRestSecretId']
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
        assert errors['_'] == 'Can\'t modify usage as this secret is in use', \
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
        assert errors['_'] == 'Encryption secret not allowed', \
               f'unexpected error: {errors}'

        secret['data']['encryptSecretId'] = good_secret_id
        secret_id = create_secret(self.random_node(), secret)

        secret['data']['encryptSecretId'] = bad_secret_id
        errors = update_secret(self.random_node(), secret_id, secret,
                               expected_code=400)
        assert errors['_'] == 'Encryption secret not allowed', \
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
        assert errors['_'] == 'Can\'t modify usage as this secret is in use', \
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

        rotation_days = 3
        next_rotation = (now(-7) + moment).isoformat()
        secret = auto_generated_secret(auto_rotation=True,
                                       rotation_interval=rotation_days,
                                       next_rotation_time=next_rotation)
        secret_id = create_secret(self.random_node(), secret)

        def rotation_happened(key_num, expected_rotation_time_iso):
            s = get_secret(self.random_node(), secret_id)
            if len(s['data']['keys']) < key_num:
                return False
            assert 'lastRotationTime' in s['data'], f'no lastRotationTime: {s}'
            rotation_time_iso = s['data']['lastRotationTime']
            rotation_time = parse_iso8601(rotation_time_iso)
            expected_time = parse_iso8601(expected_rotation_time_iso)
            assert rotation_time >= expected_time, \
                   f'rotation happened too early'
            assert (rotation_time - expected_time).seconds <= 10, \
                   f'rotation happend too late'
            next_rotation_time_iso = s['data']['nextRotationTime']
            next_rotation_time = parse_iso8601(next_rotation_time_iso)
            expected_next_rotation_time = expected_time + \
                                          timedelta(days=rotation_days)
            assert next_rotation_time == expected_next_rotation_time, \
                   f'bad next rotation time, got: {next_rotation_time}, ' \
                   f'expected: {expected_next_rotation_time}'
            return True

        testlib.poll_for_condition(
            lambda: rotation_happened(2, next_rotation),
            sleep_time=0.3, timeout=30)

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
            sleep_time=0.3, timeout=30)

    def cfg_encryption_api_test(self):
        secret = auto_generated_secret(usage=['bucket-encryption-*'])
        bad_id = create_secret(self.random_node(), secret)
        secret['usage'] = ['bucket-encryption-*', 'configuration-encryption']
        secret['name'] = secret['name'] + ' (good)' # has to be unique
        good_id = create_secret(self.random_node(), secret)
        node = self.random_node()
        # There is a secret that is encrypted by master password; if we disable
        # config encryption that secret we be stored unencrypted in chronicle
        set_cfg_encryption(node, 'disabled', -1, expected_code=400)
        set_cfg_encryption(node, 'encryption_service', -1)
        set_cfg_encryption(node, 'secret', -1, expected_code=400)
        set_cfg_encryption(node, 'secret', bad_id, expected_code=400)
        set_cfg_encryption(node, 'secret', good_id)

        secret['usage'] = ['bucket-encryption-*']
        errors = update_secret(node, good_id, secret, expected_code=400)
        assert errors['_'] == 'Can\'t modify usage as this secret is in use', \
               f'unexpected error: {errors}'

        set_cfg_encryption(node, 'encryption_service', -1)

        update_secret(node, good_id, secret)

    def dont_store_secret_in_unencrypted_chronicle_test(self):
        node = self.random_node()
        set_cfg_encryption(node, 'disabled', -1)

        secret = auto_generated_secret()
        # Can't create secret because it will be stored unencrypted in
        # chronicle then
        create_secret(node, secret, expected_code=400)

        # Enabled config encryption and try again. Now creation works:
        set_cfg_encryption(node, 'encryption_service', -1)
        secret_id = create_secret(node, secret)

        # ... and can't disable config encryption anymore:
        set_cfg_encryption(node, 'disabled', -1, expected_code=400)

        # Now try encrypt that secret by another secret. It should become
        # posible to store it in unencrypted chronicle then
        aws_secret = aws_test_secret(name='AWS Key',
                                     usage=['secrets-encryption'])
        aws_secret_id = create_secret(node, aws_secret)
        secret['data']['encryptBy'] = 'clusterSecret'
        secret['data']['encryptSecretId'] = aws_secret_id
        update_secret(node, secret_id, secret)

        # Now we can disable config encryption:
        set_cfg_encryption(node, 'disabled', -1)

        # ... but can't update the secret to use "master password" again
        secret['data']['encryptBy'] = 'nodeSecretManager'
        secret['data']['encryptSecretId'] = -1
        update_secret(node, secret_id, secret, expected_code=400)

    def dump_keks_test(self):
        secret = auto_generated_secret()
        node = self.random_node()
        secret_id = create_secret(node, secret)
        n = 5
        for i in range(n):
            rotate_secret(node, secret_id)

        ids = get_all_kek_ids(node, secret_id)
        testlib.assert_eq(len(ids), n + 1)
        unknown_id = 'unknown'
        res = run_dump_keys(node, ['--key-kind', 'kek', \
                                   '--key-ids', unknown_id] + ids)

        verify_key_presense_in_dump_key_response(res, ids, [unknown_id])

        # Make sure that we return correct code and error in case
        # of wrong password (other utilities can rely on that)
        wrong_password = testlib.random_str(8)
        error = run_dump_keys(node,
                              ['-p', wrong_password, '--key-kind', 'kek', \
                               '--key-ids', unknown_id] + ids,
                              expected_return_code=2)
        assert error == 'Incorrect master password\n', \
               f'unexpected error: {error}'

        # Make sure incorrect args don't lead to exit code 2 (used to be
        # the case), so it is not mixed with incorrect password
        run_dump_keys(node,
                      ['-p', wrong_password, '--key-kind', 'kek'],
                       expected_return_code=1)

    def dump_bucket_deks_test(self):
        secret = auto_generated_secret(usage=['bucket-encryption-*'])
        secret_id = create_secret(self.random_node(), secret)
        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestSecretId': secret_id}
        self.cluster.create_bucket(bucket_props, sync=True)
        node = self.random_node()
        ids = get_key_list(node, '{bucketDek, \'' + self.bucket_name + '\'}')
        print(ids)
        unknown_id = 'unknown'
        res = run_dump_bucket_deks(node, ['--bucket', self.bucket_name,
                                          '--key-ids', unknown_id] + ids)

        verify_key_presense_in_dump_key_response(res, ids, [unknown_id])

        # making sure that we return correct code and error in case
        # of wrong password (other utilities can rely on that)
        wrong_password = testlib.random_str(8)
        error = run_dump_bucket_deks(node,
                                     ['-p', wrong_password,
                                      '--bucket', self.bucket_name,
                                      '--key-ids', unknown_id] + ids,
                                     expected_return_code=2)
        assert error == 'Incorrect master password\n', \
               f'unexpected error: {error}'

        # Make sure incorrect args don't lead to exit code 2 (used to be
        # the case), so it is not mixed with incorrect password
        run_dump_bucket_deks(node,
                             ['-p', wrong_password,
                              '--bucket', self.bucket_name],
                             expected_return_code=1)

    def config_dek_automatic_rotation_test(self):
        # Enable encryption and set dek rotation int = 1 sec
        # Wait some time and check if dek has rotated
        secret = auto_generated_secret(usage=['configuration-encryption'])
        secret_id = create_secret(self.random_node(), secret)
        kek_id = get_kek_id(self.random_node(), secret_id)
        set_cfg_encryption(self.random_node(), 'secret', secret_id,
                           dek_rotation=60*60*24*30)

        dek_path = Path() / 'config' / 'deks'

        current_dek_ids = poll_verify_deks_and_collect_ids(self.cluster,
                                                           dek_path,
                                                           verify_key_count=1)

        rotation_enabling_time = datetime.now(timezone.utc)

        set_cfg_encryption(self.random_node(), 'secret', secret_id,
                           dek_rotation=1)

        time.sleep(2) # let it rotate deks

        set_cfg_encryption(self.random_node(), 'secret', secret_id,
                           dek_rotation=60*60*24*30)

        # Verify that current dek was created after we've enabled the rotation
        def verify_ct(ct_str):
            key_creation_time = parse_iso8601(ct_str)
            return key_creation_time > rotation_enabling_time

        # Verify that config dek dir has only one dek (all old deks are
        # supposed to be removed immediatelly for config encryption)
        # Also verify that all deks existed before the rotation are gone now
        poll_verify_dek_files(self.cluster, dek_path,
                              verify_key_count=1,
                              verify_creation_time=verify_ct,
                              verify_encryption_kek=kek_id,
                              verify_id=lambda n: n not in current_dek_ids)

    def bucket_dek_automatic_rotation_test(self):
        # Enable encryption and set dek rotation int = 1 sec
        # Wait some time and check if dek has rotated
        secret = auto_generated_secret(usage=['bucket-encryption-*'])
        secret_id = create_secret(self.random_node(), secret)
        kek_id = get_kek_id(self.random_node(), secret_id)

        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestSecretId': secret_id},
                                   sync=True)
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1)

        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestDekRotationInterval': 1})

        time.sleep(2) # let it rotate deks

        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestDekRotationInterval': 0})

        # Verify that bucket has more than one dek now
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=lambda n: n > 1)

    def basic_aws_secret_test(self):
        # Create an AWS key and use it to encrypt bucket, config, and secrets
        secret_json = aws_test_secret(name='AWS Key',
                                      usage=['bucket-encryption-*',
                                             'configuration-encryption',
                                             'secrets-encryption'])
        aws_secret_id = create_secret(self.random_node(), secret_json)
        kek_id = get_kek_id(self.random_node(), aws_secret_id)

        # Create a bucket and encrypt it using AWS key:
        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestSecretId': aws_secret_id}
        self.cluster.create_bucket(bucket_props)

        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=kek_id)

        # Use AWS key to encrypt configuration
        set_cfg_encryption(self.random_node(), 'secret', aws_secret_id)
        dek_path = Path() / 'config' / 'deks'
        poll_verify_dek_files(self.cluster,
                              dek_path,
                              verify_key_count=1,
                              verify_encryption_kek=kek_id)

        # Create an generated secret and encrypt it with AWS secret
        generated_secret = auto_generated_secret(
                             name='test',
                             encrypt_by='clusterSecret',
                             encrypt_secret_id=aws_secret_id)
        generated_secret_id = create_secret(self.random_node(),
                                            generated_secret)
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), generated_secret_id),
                         verify_encryption_kek=kek_id,
                         verify_key_count=1)

        # Can't delete because it is in use
        delete_secret(self.random_node(), aws_secret_id, expected_code=400)

    def dek_limit_test(self):
        set_cfg_dek_limit(self.cluster, 2)
        set_bucket_dek_limit(self.cluster, self.bucket_name, 2)

        secret = auto_generated_secret(
                     usage=[f'bucket-encryption-{self.bucket_name}',
                            'configuration-encryption'])
        secret_id = create_secret(self.random_node(), secret)

        set_cfg_encryption(self.random_node(), 'secret', secret_id,
                           dek_rotation=1)
        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestSecretId': secret_id,
                                    'encryptionAtRestDekRotationInterval': 1},
                                   sync=True)

        time.sleep(3)

        verify_bucket_deks_files(self.cluster, self.bucket_name,
                                 verify_key_count=lambda n: n <= 2)

        verify_dek_files(self.cluster, Path() / 'config' / 'deks',
                         verify_key_count=lambda n: n <= 2)


class NativeEncryptionPermissionsTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition='Enterprise')

    def setup(self):
        set_cfg_encryption(self.cluster, 'encryption_service', -1)
        self.bucket_name = testlib.random_str(8)
        self.password = testlib.random_str(8)
        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestSecretId': -1}
        self.cluster.create_bucket(bucket_props, sync=True)
        self.pre_existing_ids = [s['id'] for s in get_secrets(self.cluster)]

        create_user = lambda n, r: put_user(self.cluster, 'local', n,
                                            password=self.password, roles=r)

        admin = 'admin_' + testlib.random_str(4)
        create_user(admin, 'admin')

        ro_admin = 'ro_admin_' + testlib.random_str(4)
        create_user(ro_admin, 'ro_admin')

        bucket_creator = 'bucket_creator_' + testlib.random_str(4)
        create_user(bucket_creator, 'cluster_admin')

        bucket_admin = 'bucket_admin_' + testlib.random_str(4)
        create_user(bucket_admin, f'bucket_admin[{self.bucket_name}]')

        bucket_reader = 'bucket_reader_' + testlib.random_str(4)
        create_user(bucket_reader, f'data_reader[{self.bucket_name}]')

        no_priv_user = 'no_priv_user_' + testlib.random_str(4)
        create_user(no_priv_user, f'external_stats_reader')

        # Usages:
        cfg = 'configuration-encryption'
        sec = 'secrets-encryption'
        all_b = 'bucket-encryption-*'
        b = f'bucket-encryption-{self.bucket_name}'

        self.writing = \
            {admin:          {cfg: True,  sec: True,  all_b: True,  b: True},
             ro_admin:       {cfg: False, sec: False, all_b: False, b: False},
             bucket_creator: {cfg: False, sec: False, all_b: True,  b: True},
             bucket_admin:   {cfg: False, sec: False, all_b: False, b: True} ,
             bucket_reader:  {cfg: False, sec: False, all_b: False, b: False},
             no_priv_user:   {cfg: False, sec: False, all_b: False, b: False}}

        self.reading = \
            {admin:          {cfg: True,  sec: True,  all_b: True,  b: True},
             ro_admin:       {cfg: True,  sec: True,  all_b: True,  b: True},
             bucket_creator: {cfg: False, sec: False, all_b: True,  b: True},
             bucket_admin:   {cfg: False, sec: False, all_b: True,  b: True} ,
             bucket_reader:  {cfg: False, sec: False, all_b: True,  b: True},
             no_priv_user:   {cfg: False, sec: False, all_b: False, b: False}}

    def teardown(self):
        self.cluster.delete_bucket(self.bucket_name)
        for u in self.writing:
            testlib.ensure_deleted(
                self.cluster, f'/settings/rbac/users/local/{u}')
        set_cfg_encryption(self.cluster, 'disabled', -1)

    def test_teardown(self):
        for s in get_secrets(self.cluster):
            if s['id'] not in self.pre_existing_ids:
                delete_secret(self.cluster, s['id'])

    def secrets_test_gen(self):
        tests = {}
        for user in self.writing:
            for usage in self.writing[user]:
                tests[f'create_secret({user}, {usage})'] = \
                    lambda s, n=user, u=usage: s.create_secret_test_(n, u)
                tests[f'update_secret({user}, {usage})'] = \
                    lambda s, n=user, u=usage: s.update_secret_test_(n, u)
                tests[f'read_secret({user}, {usage})'] = \
                    lambda s, n=user, u=usage: s.read_secret_test_(n, u)
        return tests

    def create_secret_test_(self, username, usage):
        creds = (username, self.password)
        secret = auto_generated_secret(usage=[usage])
        expected_code = 200 if self.writing[username][usage] else 403
        create_secret(self.cluster, secret, auth=creds,
                      expected_code=expected_code)

    def update_secret_test_(self, username, usage):
        creds = (username, self.password)
        secret = auto_generated_secret(usage=[usage])
        secret_id = create_secret(self.cluster, secret) # note: admin creates it
        secret['name'] = secret['name'] + ' foo'
        expected_code = 200 if self.writing[username][usage] else 403
        update_secret(self.cluster, secret_id, secret, auth=creds,
                      expected_code=expected_code)
        delete_secret(self.cluster, secret_id, auth=creds,
                      expected_code=expected_code)

    def read_secret_test_(self, name, usage):
        creds = (name, self.password)
        forbidden = [u for u in self.reading[name] if not self.reading[name][u]]
        secret_with_usage = auto_generated_secret(usage=[usage] + forbidden)
        # Note: admin creates this secret
        secret_with_usage_id = create_secret(self.cluster, secret_with_usage)

        # All usages but one are unreadable, so readability of this secret
        # depends on readability of 'usage'
        should_be_readable = self.reading[name][usage]
        expected_code = 200 if should_be_readable else 404
        get_secret(self.cluster, secret_with_usage_id, auth=creds,
                   expected_code=expected_code)

        secrets = get_secrets(self.cluster, auth=creds)
        filtered = [s for s in secrets if s['id'] == secret_with_usage_id]
        if should_be_readable:
            assert len(filtered) == 1, f'unexpected secrets: {secrets}'
        else:
            assert len(filtered) == 0, f'unexpected secrets: {secrets}'

        if len(forbidden) > 0:
            not_readable_secret = auto_generated_secret(usage=forbidden)
            # Note: admin creates this secret
            not_readable_secret_id = create_secret(self.cluster,
                                                   not_readable_secret)
            get_secret(self.cluster, not_readable_secret_id, auth=creds,
                       expected_code=404)
            secrets = get_secrets(self.cluster, auth=creds)
            filtered = [s for s in secrets if s['id'] == not_readable_secret]
            assert filtered == [], f'unexpected secrets: {secrets}'


def get_key_list(node, kind_as_str):
    res = testlib.diag_eval(
            node,
            '{ok, {_, List, _}} = cb_deks:list(' + kind_as_str + '), ' \
            'lists:flatten(lists:join(",", [binary_to_list(K) || K <- List])).')
    if res.text == "[]":
        return []
    re_res = re.search('"(.*)"', res.text)
    assert re_res is not None, f'unexpected diag eval return: {res.text}'
    keys_str = re_res.group(1)
    return keys_str.split(',')


def run_dump_keys(node, *args, **kwargs):
    return run_dump_key_utility(node, 'dump-keys', *args, **kwargs)


def run_dump_bucket_deks(node, *args, **kwargs):
    return run_dump_key_utility(node, 'dump-bucket-deks', *args, **kwargs)


def run_dump_key_utility(node, name, args, expected_return_code=0):
    data_dir = node.data_path()
    gosecrets_cfg_path = os.path.join(data_dir, 'config', 'gosecrets.cfg')
    gosecrets_path = os.path.join(testlib.get_ns_server_dir(),
                                  'build', 'deps', 'gocode', 'gosecrets')
    utility_path = os.path.join(testlib.get_scripts_dir(), name)
    pylib_path = testlib.get_pylib_dir()
    all_args = ['--config', gosecrets_cfg_path,
                '--gosecrets', gosecrets_path] + args
    env = {'PYTHONPATH': pylib_path, "PATH": os.environ['PATH']}
    r = subprocess.run([utility_path] + all_args, capture_output=True, env=env)
    assert r.returncode == expected_return_code, \
           f'{name} returned {r.returncode}\n' \
           f'stdout: {r.stdout.decode()}\n' \
           f'stderr: {r.stderr.decode()}'
    print(f'{name} reponse: {r.stdout.decode()}')
    if expected_return_code == 0:
        return json.loads(r.stdout)

    return r.stderr.decode()


def verify_key_presense_in_dump_key_response(response, good_ids, unknown_ids):
    for k in good_ids:
        testlib.assert_in(k, response)
        testlib.assert_in('result', response[k])
        testlib.assert_eq(response[k]['result'], 'raw-aes-gcm')
        testlib.assert_in('key', response[k]['response'])
        key = base64.b64decode(response[k]['response']['key'])
        testlib.assert_eq(len(key), 32)

    for k in unknown_ids:
        testlib.assert_in(k, response)
        testlib.assert_in('result', response[k])
        testlib.assert_eq(response[k]['result'], 'error')


def set_cfg_encryption(cluster, mode, secret, dek_lifetime=60*60*24*365,
                       dek_rotation=60*60*24*30, expected_code=200):
    testlib.post_succ(cluster, '/settings/security/encryptionAtRest/config',
                      json={'encryptionMethod': mode,
                            'encryptionSecretId': secret,
                            'dekLifetime': dek_lifetime,
                            'dekRotationInterval': dek_rotation},
                      expected_code=expected_code)
    if expected_code == 200:
        r = testlib.get_succ(cluster, '/settings/security/encryptionAtRest')
        r = r.json()
        testlib.assert_eq(r['config']['encryptionMethod'], mode)
        testlib.assert_eq(r['config']['encryptionSecretId'], secret)


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

# This secret does not actually go to aws when asked encrypt or decrypt data.
# All AWS secrets with special ARN=TEST_AWS_KEY_ARN simply encrypt data using
# dummy key.
def aws_test_secret(name=None, usage=None):
    if usage is None:
        usage = ['bucket-encryption-*', 'secrets-encryption']
    if name is None:
        name = f'Test secret {testlib.random_str(5)}'

    return {'name': name,
            'type': 'awskms-aes-key-256',
            'usage': usage,
            'data': {'keyARN': 'TEST_AWS_KEY_ARN'}}


def get_secret(cluster, secret_id, expected_code=200, auth=None):
    if auth is None:
        auth = cluster.auth
    r = testlib.get_succ(cluster, f'/settings/secrets/{secret_id}',
                         expected_code=expected_code, auth=auth)
    if expected_code == 200:
        return r.json()
    return r.text


def get_secrets(cluster, auth=None):
    if auth is None:
        auth = cluster.auth
    return testlib.get_succ(cluster, '/settings/secrets', auth=auth).json()


def create_secret(cluster, json, expected_code=200, auth=None):
    if auth is None:
        auth = cluster.auth
    r = testlib.post_succ(cluster, '/settings/secrets', json=json,
                          expected_code=expected_code, auth=auth)


    if expected_code == 200:
        r = r.json()
        return r['id']
    elif expected_code == 403:
        return r.text
    else:
        r = r.json()
        return r['errors']


def update_secret(cluster, secret_id, json, expected_code=200, auth=None):
    if auth is None:
        auth = cluster.auth
    r = testlib.put_succ(cluster, f'/settings/secrets/{secret_id}', json=json,
                         expected_code=expected_code, auth=auth)
    if expected_code == 200:
        r = r.json()
        return r['id']
    elif expected_code == 403:
        return r.text
    elif expected_code == 404:
        return r.text
    else:
        r = r.json()
        return r['errors']


def delete_secret(cluster, secret_id, expected_code=200, auth=None):
    if auth is None:
        auth = cluster.auth
    testlib.delete(cluster, f'/settings/secrets/{secret_id}',
                   expected_code=expected_code, auth=auth)


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


def verify_bucket_deks_files(cluster, bucket, **kwargs):
    deks_path = Path() / 'data' / bucket / 'deks'

    def is_kv_node(node):
        return Service.KV in node.get_services()

    def is_not_kv_node(node):
        return not is_kv_node(node)

    verify_dek_files(cluster, deks_path, node_filter=is_kv_node, **kwargs)
    verify_dek_files(cluster, deks_path, node_filter=is_not_kv_node,
                     verify_key_count=0)


def verify_dek_files(cluster, relative_path, verify_key_count=1,
                     node_filter=None, **kwargs):
    for node in cluster.connected_nodes:
        deks_path = Path(node.data_path()) / relative_path
        print(f'Checking deks in {deks_path} (cheking ' \
              f'verify_key_count={verify_key_count} and also {kwargs})... ')
        if node_filter is not None:
            if not node_filter(node):
                print(f'Skipping check of {node}')
                continue
        if not deks_path.exists():
            if verify_key_count == 0:
                return
            else:
                assert False, f'directory {deks_path} doesn\'t exist'
        c = 0
        for path in deks_path.iterdir():
            if is_valid_key_id(path.name):
                c += 1
                verify_key_file(path, **kwargs)
            else:
                print(f'Skipping file {path} (doesn\'t seem to be a key file)')

        if verify_key_count is not None:
            if callable(verify_key_count):
                assert verify_key_count(c), f'dek count is unexpected: {c}'
            else:
                assert c == verify_key_count, f'dek count is unexpected: {c} ' \
                                              f'(expected: {verify_key_count})'


def is_valid_key_id(name):
    # Just testing that it is a uuid. This solution is not perfect but helps
    # most of the time (e.g. when some temporary file is found in dek directory)
    try:
        return name == str(uuid.UUID(name))
    except ValueError:
        return False


def poll_verify_bucket_deks_files(*args, **kwargs):
    testlib.poll_for_condition(
      lambda: verify_bucket_deks_files(*args, **kwargs),
      sleep_time=0.2, attempts=50, retry_on_assert=True, verbose=True)


def poll_verify_dek_files(*args, **kwargs):
    testlib.poll_for_condition(
      lambda: verify_dek_files(*args, **kwargs),
      sleep_time=0.2, attempts=50, retry_on_assert=True, verbose=True)


def verify_key_file(path, verify_missing=False, verify_encryption_kek=None,
                    verify_creation_time=None, verify_id=None):
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
        if verify_creation_time is not None:
            ct = content['keyData']['creationTime']
            assert verify_creation_time(ct), \
                   f'Unexpected key creation time: {ct} ' \
                   f'(cur time: {datetime.now(timezone.utc)})'
        if verify_id is not None:
            assert verify_id(path.name), f'unexpected key id: {path.name}'
        assert content['type'] == 'raw-aes-gcm'


def get_kek_id(cluster, secret_id):
    r = get_secret(cluster, secret_id)
    if r['type'] == 'auto-generated-aes-key-256':
        for k in r['data']['keys']:
            if k['active']:
                return k['id']
    if r['type'] == 'awskms-aes-key-256':
        return r['data']['storedKeyIds'][0]['id']
    return None


def get_all_kek_ids(cluster, secret_id):
    r = get_secret(cluster, secret_id)
    if r['type'] == 'auto-generated-aes-key-256':
        return [k['id'] for k in r['data']['keys']]
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


def poll_verify_deks_and_collect_ids(*args, **kwargs):
    current_dek_ids = []

    def collect_ids(dek_id):
        current_dek_ids.append(dek_id)
        return True

    def verify():
        current_dek_ids = []
        verify_dek_files(verify_id=collect_ids, *args, **kwargs)

    testlib.poll_for_condition(
      verify, sleep_time=0.2, attempts=50, retry_on_assert=True, verbose=True)

    print(f'key list extracted: {current_dek_ids}')

    return current_dek_ids


def set_cfg_dek_limit(cluster, n):
    key = '{cb_cluster_secrets, {max_dek_num, configDek}}'
    if n is None:
        testlib.diag_eval(cluster, f'ns_config:delete({key}).')
    else:
        testlib.diag_eval(cluster, f'ns_config:set({key}, {n}).')


def set_bucket_dek_limit(cluster, bucket, n):
    key = '{cb_cluster_secrets, {max_dek_num, {bucketDek, "' + bucket + '"}}}'
    if n is None:
        testlib.diag_eval(cluster, f'ns_config:delete({key}).')
    else:
        testlib.diag_eval(cluster, f'ns_config:set({key}, {n}).')


def parse_iso8601(s):
    # can't use datetime.fromisoformat because it doesn't parse UTC datetimes
    # before version 3.11
    return dateutil.parser.parse(s)
