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
from testsets.sample_buckets import SampleBucketTasksBase
from testsets.users_tests import put_user

encrypted_file_magic = b'\x00Couchbase Encrypted\x00'
min_timer_interval = 1 # seconds

class NativeEncryptionTests(testlib.BaseTestSet, SampleBucketTasksBase):

    def __init__(self, cluster):
        super().__init__(cluster)
        SampleBucketTasksBase.__init__(self)

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes = 3,
                                           edition='Enterprise',
                                           services={'n0': [Service.KV],
                                                     'n1': [Service.QUERY],
                                                     'n2': [Service.KV]},
                                           buckets=[],
                                           balanced=True)

    def setup(self):
        # Wait for orchestrator to move to non kv node.
        # Here we assume that there is only one non kv node:
        set_min_timer_interval(self.cluster, min_timer_interval)
        non_kv_node = None
        for n in self.cluster.connected_nodes:
            if Service.KV not in n.get_services():
                assert non_kv_node is None
                non_kv_node = n
        assert non_kv_node is not None
        self.cluster.wait_for_orchestrator(non_kv_node)

        # since master password is per-node, we should use the same node for
        # all HTTP requests in all tests that use node secret management (SM)
        self.sm_node = random.choice(self.cluster.connected_nodes)
        self.bucket_name = testlib.random_str(8)
        set_cfg_encryption(self.cluster, 'nodeSecretManager', -1)
        self.sample_bucket = "beer-sample"
        # Creating a few keys whose role is to just exist while other tests
        # are running. It increases code coverage.
        id1 = create_secret(self.random_node(), aws_test_secret())
        id2 = create_secret(self.random_node(),
                            auto_generated_secret(encrypt_with='encryptionKey',
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
        set_min_timer_interval(self.cluster, None)

    def test_teardown(self):
        set_cfg_encryption(self.cluster, 'nodeSecretManager', -1)
        set_log_encryption(self.cluster, 'disabled', -1)
        self.cluster.delete_bucket(self.bucket_name)
        self.cluster.delete_bucket(self.sample_bucket)
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
        secret_list = get_secrets(self.random_node())
        assert len(secret_list) == start_len + 1, \
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
                        'encryptionAtRestKeyId': secret1_id + 1}
        resp = self.cluster.create_bucket(bucket_props, expected_code=400)
        errors = resp.json()
        e = errors['errors']['encryptionAtRestKeyId']
        assert e == 'Encryption key does not exist', \
               f'unexpected error: {errors}'

        bucket_props['encryptionAtRestKeyId'] = secret1_id
        self.cluster.create_bucket(bucket_props, sync=True)

        kek1_id = get_kek_id(self.random_node(), secret1_id)
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=kek1_id)

        # Can't delete because it is in use
        delete_secret(self.random_node(), secret1_id, expected_code=400)

        # Can't modify because the secret doesn't exist
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestKeyId': secret1_id + 1},
                                   expected_code=400)

        secret2_id = create_secret(self.random_node(), secret2_json)
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestKeyId': secret2_id})

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
                                    'encryptionAtRestKeyId': -1},
                                   sync=True)
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=0)
        # Can't modify because the secret doesn't exist
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestKeyId': secret1_id + 1},
                                   expected_code=400)
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestKeyId': secret1_id})
        kek1_id = get_kek_id(self.random_node(), secret1_id)
        # update is asynchronous, so we can't assume the dek gets reencrypted
        # immediately
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=kek1_id)
        # Can't delete because it is in use
        delete_secret(self.random_node(), secret1_id, expected_code=400)
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestKeyId': -1})

    def secret_not_allowed_to_encrypt_bucket_test(self):
        secret1_json = auto_generated_secret(usage=['bucket-encryption-wrong'])
        secret1_id = create_secret(self.random_node(), secret1_json)

        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestKeyId': secret1_id}

        # Trying to use a secret that is not allowed to encrypt this bucket
        resp = self.cluster.create_bucket(bucket_props, expected_code=400)
        errors = resp.json()
        e = errors['errors']['encryptionAtRestKeyId']
        assert e == 'Encryption key can\'t encrypt this bucket', \
               f'unexpected error: {errors}'

        secret1_json['usage'].append(f'bucket-encryption-{self.bucket_name}')
        update_secret(self.random_node(), secret1_id, secret1_json)

        # Now the secret should work fine for encryption
        self.cluster.create_bucket(bucket_props)

        secret2_json = auto_generated_secret(usage=['bucket-encryption-wrong'])
        secret2_id = create_secret(self.random_node(), secret2_json)

        # Trying to change encryption secret to the one that can't encrypt
        # this bucket
        bucket_props['encryptionAtRestKeyId'] = secret2_id
        resp = self.cluster.update_bucket(bucket_props, expected_code=400)
        errors = resp.json()
        e = errors['errors']['encryptionAtRestKeyId']
        assert e == 'Encryption key can\'t encrypt this bucket', \
               f'unexpected error: {errors}'

        # Trying to forbid using this secret for our bucket encryption
        del secret1_json['usage'][1]
        errors = update_secret(self.random_node(), secret1_id, secret1_json,
                               expected_code=400)
        assert errors['_'] == 'Can\'t modify usage as this key is in use', \
               f'unexpected error: {errors}'

        # Trying again, but now we add permission to encrypt all buckets
        secret1_json['usage'].append('bucket-encryption')
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
            sleep_time=0.3, attempts=50, retry_on_assert=True, verbose=True)
        check_decrypt(self.sm_node, kek_id, encrypted, data)

        # Testing that config deks are also reencrypted
        # Cache reset should fail if it can't read keys from disk
        testlib.diag_eval(
          self.sm_node,
          '{ok, changed} = cb_crypto:reset_dek_cache(configDek, cleanup).')

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
                                    'encryptionAtRestKeyId': secret2_id},
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
                                             encrypt_with='encryptionKey',
                                             encrypt_secret_id=secret1_id))
        secret3_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Level 2 (key3)',
                                             encrypt_with='encryptionKey',
                                             encrypt_secret_id=secret1_id))
        secret4_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Level 3 (key4)',
                                             encrypt_with='encryptionKey',
                                             encrypt_secret_id=secret2_id))
        secret5_id = create_secret(
                       self.random_node(),
                       auto_generated_secret(name='Level 3 (key5)',
                                             encrypt_with='encryptionKey',
                                             encrypt_secret_id=secret3_id))

        # Can't create secret because encryption key with such id doesn't exist
        create_secret(self.random_node(),
                      auto_generated_secret(name='key6',
                                            encrypt_with='encryptionKey',
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
                                                 usage=['bucket-encryption',
                                                        'KEK-encryption']))
        bad_secret_id = create_secret(
                          self.random_node(),
                          auto_generated_secret(name='Bad Secret',
                                                usage=['bucket-encryption']))

        secret = auto_generated_secret(name='Lever 2 (key1)',
                                       encrypt_with='encryptionKey',
                                       encrypt_secret_id=bad_secret_id)

        errors = create_secret(self.random_node(), secret, expected_code=400)
        assert errors['_'] == 'Encryption key not allowed', \
               f'unexpected error: {errors}'

        secret['data']['encryptWithKeyId'] = good_secret_id
        secret_id = create_secret(self.random_node(), secret)

        secret['data']['encryptWithKeyId'] = bad_secret_id
        errors = update_secret(self.random_node(), secret_id, secret,
                               expected_code=400)
        assert errors['_'] == 'Encryption key not allowed', \
               f'unexpected error: {errors}'

    def change_encrypt_id_for_kek_test(self):
        secret1_id = create_secret(self.random_node(),
                                   auto_generated_secret(name='Root 1'))
        secret2_id = create_secret(self.random_node(),
                                   auto_generated_secret(name='Root 2'))
        secret3 = auto_generated_secret(name='Lever 2 (key1)',
                                        encrypt_with='encryptionKey',
                                        encrypt_secret_id=secret1_id)
        secret3_id = create_secret(self.random_node(), secret3)

        kek1_id = get_kek_id(self.random_node(), secret1_id)
        verify_kek_files(self.cluster,
                         get_secret(self.random_node(), secret3_id),
                         verify_encryption_kek=kek1_id)

        # Try encrypting secret3 with another secret
        secret3['data']['encryptWithKeyId'] = secret2_id
        update_secret(self.random_node(), secret3_id, secret3)
        kek2_id = get_kek_id(self.random_node(), secret2_id)
        poll_verify_kek_files(self.cluster,
                              get_secret(self.random_node(), secret3_id),
                              verify_encryption_kek=kek2_id)

        # Try encrypt secret3 with node secret manager
        del secret3['data']['encryptWithKeyId']
        secret3['data']['encryptWith'] = 'nodeSecretManager'
        update_secret(self.random_node(), secret3_id, secret3)
        poll_verify_kek_files(self.cluster,
                              get_secret(self.random_node(), secret3_id),
                              verify_encryption_kek='encryptionService')

        # Try encrypting secret3 with secret1 again
        secret3['data']['encryptWithKeyId'] = secret1_id
        secret3['data']['encryptWith'] = 'encryptionKey'
        update_secret(self.random_node(), secret3_id, secret3)
        kek1_id = get_kek_id(self.random_node(), secret1_id)
        poll_verify_kek_files(self.cluster,
                              get_secret(self.random_node(), secret3_id),
                              verify_encryption_kek=kek1_id)

        # Try encrypting secret with itself (must fail)
        secret3['data']['encryptWithKeyId'] = secret3_id
        update_secret(self.random_node(), secret3_id, secret3,
                      expected_code=400)

    def change_secret_usage_test(self):
        secret1 = auto_generated_secret(usage=['KEK-encryption'])
        secret1_id = create_secret(self.random_node(), secret1)

        secret2 = auto_generated_secret(encrypt_with='encryptionKey',
                                        encrypt_secret_id=secret1_id)
        secret2_id = create_secret(self.random_node(), secret2)

        # Can't remove 'KEK-encryption' usage because this secret is
        # currently encrypting another secret
        secret1['usage'] = ['bucket-encryption']
        errors = update_secret(self.random_node(), secret1_id, secret1,
                               expected_code=400)
        assert errors['_'] == 'Can\'t modify usage as this key is in use', \
               f'unexpected error: {errors}'

        # Stop using secret1 for encryption
        del secret2['data']['encryptWithKeyId']
        secret2['data']['encryptWith'] = 'nodeSecretManager'
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
                                             encrypt_with='encryptionKey',
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
                                    'encryptionAtRestKeyId': secret1_id},
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
            # rotation can happen later ns_server does not allow timers
            # to fire more often than once per min_timer_interval
            delta = (rotation_time - expected_time).seconds
            assert delta <= min_timer_interval + 10, \
                   f'rotation happend too late, delta: {delta} seconds'
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
            sleep_time=1, timeout=min_timer_interval + 30)

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
        secret = auto_generated_secret(usage=['bucket-encryption'])
        bad_id = create_secret(self.random_node(), secret)
        secret['usage'] = ['bucket-encryption', 'config-encryption']
        secret['name'] = secret['name'] + ' (good)' # has to be unique
        good_id = create_secret(self.random_node(), secret)
        node = self.random_node()
        # There is a secret that is encrypted by master password; if we disable
        # config encryption that secret we be stored unencrypted in chronicle
        set_cfg_encryption(node, 'disabled', -1, expected_code=400)
        set_cfg_encryption(node, 'nodeSecretManager', -1)
        set_cfg_encryption(node, 'encryptionKey', -1, expected_code=400)
        set_cfg_encryption(node, 'encryptionKey', bad_id, expected_code=400)
        set_cfg_encryption(node, 'encryptionKey', good_id)

        secret['usage'] = ['bucket-encryption']
        errors = update_secret(node, good_id, secret, expected_code=400)
        assert errors['_'] == 'Can\'t modify usage as this key is in use', \
               f'unexpected error: {errors}'

        set_cfg_encryption(node, 'nodeSecretManager', -1)

        update_secret(node, good_id, secret)

    def dont_store_secret_in_unencrypted_chronicle_test(self):
        node = self.random_node()
        set_cfg_encryption(node, 'disabled', -1)

        secret = auto_generated_secret()
        # Can't create secret because it will be stored unencrypted in
        # chronicle then
        create_secret(node, secret, expected_code=400)

        # Enabled config encryption and try again. Now creation works:
        set_cfg_encryption(node, 'nodeSecretManager', -1)
        secret_id = create_secret(node, secret)

        # ... and can't disable config encryption anymore:
        set_cfg_encryption(node, 'disabled', -1, expected_code=400)

        # Now try encrypt that secret by another secret. It should become
        # posible to store it in unencrypted chronicle then
        aws_secret = aws_test_secret(name='AWS Key',
                                     usage=['KEK-encryption'])
        aws_secret_id = create_secret(node, aws_secret)
        secret['data']['encryptWith'] = 'encryptionKey'
        secret['data']['encryptWithKeyId'] = aws_secret_id
        update_secret(node, secret_id, secret)

        # Now we can disable config encryption:
        set_cfg_encryption(node, 'disabled', -1)

        # ... but can't update the secret to use "master password" again
        secret['data']['encryptWith'] = 'nodeSecretManager'
        secret['data']['encryptWithKeyId'] = -1
        update_secret(node, secret_id, secret, expected_code=400)

        # Switching secret back to nodeSecretManager so it can be removed
        # in teardown
        set_cfg_encryption(node, 'nodeSecretManager', -1)
        update_secret(node, secret_id, secret)

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

        keys_path = Path(node.data_path()) / 'config' / 'keks'
        res = run_dump_keys(node, ['--key-dir', keys_path,
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
        secret = auto_generated_secret(usage=['bucket-encryption'])
        secret_id = create_secret(self.random_node(), secret)
        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestKeyId': secret_id}
        self.cluster.create_bucket(bucket_props, sync=True)
        node = self.random_node()
        ids = get_key_list(node, '{bucketDek, \'' + self.bucket_name + '\'}')
        print(ids)
        unknown_id = 'unknown'
        res = run_dump_bucket_deks(node, ['--bucket', self.bucket_name,
                                          '--key-ids', unknown_id] + ids)

        verify_key_presense_in_dump_key_response(res, ids, [unknown_id])

        keys_path = Path(node.data_path()) / 'data' / self.bucket_name / 'deks'
        res = run_dump_bucket_deks(node, ['--key-dir', keys_path,
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
        secret = auto_generated_secret(usage=['config-encryption'])
        secret_id = create_secret(self.random_node(), secret)
        kek_id = get_kek_id(self.random_node(), secret_id)
        set_cfg_encryption(self.random_node(), 'encryptionKey', secret_id,
                           dek_rotation=60*60*24*30)

        dek_path = Path() / 'config' / 'deks'

        current_dek_ids = poll_verify_deks_and_collect_ids(self.cluster,
                                                           dek_path,
                                                           verify_key_count=1)

        rotation_enabling_time = datetime.now(timezone.utc)
        print(f'Rotation enabling time: {rotation_enabling_time}')

        set_cfg_encryption(self.random_node(), 'encryptionKey', secret_id,
                           dek_rotation=1)

        time.sleep(2 + min_timer_interval) # let it rotate deks

        set_cfg_encryption(self.random_node(), 'encryptionKey', secret_id,
                           dek_rotation=60*60*24*30)

        # Verify that current dek was created after we've enabled the rotation
        def verify_ct(key_creation_time):
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
        secret = auto_generated_secret(usage=['bucket-encryption'])
        secret_id = create_secret(self.random_node(), secret)
        kek_id = get_kek_id(self.random_node(), secret_id)

        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestKeyId': secret_id},
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

    def dont_remove_active_dek_test(self):
        # enable encryption and set dek lifetime = 1 sec,
        # wait some time and make sure active dek is not removed
        secret = auto_generated_secret(usage=['config-encryption'])
        secret_id = create_secret(self.random_node(), secret)
        kek_id = get_kek_id(self.random_node(), secret_id)
        set_cfg_encryption(self.random_node(), 'encryptionKey', secret_id,
                           dek_rotation=60*60*24*30,
                           dek_lifetime=1)

        dek_path = Path() / 'config' / 'deks'

        dek_ids1 = poll_verify_deks_and_collect_ids(self.cluster,
                                                    dek_path,
                                                    verify_key_count=1)

        time.sleep(2)

        dek_ids2 = poll_verify_deks_and_collect_ids(self.cluster,
                                                    dek_path,
                                                    verify_key_count=1)

        assert sorted(dek_ids1) == sorted(dek_ids2), \
               f'deks have changed: {dek_ids1} {dek_ids2}'

        set_cfg_encryption(self.random_node(), 'encryptionKey', secret_id,
                           dek_rotation=1,
                           dek_lifetime=3)

        # Dek should get rotated immediatelly because first dek is 3 sec old
        # while the rotation interval is 1 sec
        poll_verify_dek_files(self.cluster,
                              dek_path,
                              verify_key_count=1,
                              verify_id=lambda n: n not in dek_ids2)

    def basic_aws_secret_test(self):
        # Create an AWS key and use it to encrypt bucket, config, and secrets
        secret_json = aws_test_secret(name='AWS Key',
                                      usage=['bucket-encryption',
                                             'config-encryption',
                                             'KEK-encryption'])
        aws_secret_id = create_secret(self.random_node(), secret_json)
        kek_id = get_kek_id(self.random_node(), aws_secret_id)

        # Create a bucket and encrypt it using AWS key:
        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestKeyId': aws_secret_id}
        self.cluster.create_bucket(bucket_props)

        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=1,
                                      verify_encryption_kek=kek_id)

        # Use AWS key to encrypt configuration
        set_cfg_encryption(self.random_node(), 'encryptionKey', aws_secret_id)
        dek_path = Path() / 'config' / 'deks'
        poll_verify_dek_files(self.cluster,
                              dek_path,
                              verify_key_count=1,
                              verify_encryption_kek=kek_id)

        # Create an generated secret and encrypt it with AWS secret
        generated_secret = auto_generated_secret(
                             name='test',
                             encrypt_with='encryptionKey',
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
                            'config-encryption'])
        secret_id = create_secret(self.random_node(), secret)

        set_cfg_encryption(self.random_node(), 'encryptionKey', secret_id,
                           dek_rotation=1)
        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestKeyId': secret_id,
                                    'encryptionAtRestDekRotationInterval': 1},
                                   sync=True)

        time.sleep(3)

        verify_bucket_deks_files(self.cluster, self.bucket_name,
                                 verify_key_count=lambda n: n <= 2)

        verify_dek_files(self.cluster, Path() / 'config' / 'deks',
                         verify_key_count=lambda n: n <= 2)

    def prepare_cluster_for_node_readd_testing(self):
        # Create auto-generated secret for bucket encryption
        secret = auto_generated_secret(
            usage=['bucket-encryption', 'config-encryption']
        )
        secret_id = create_secret(self.random_node(), secret)
        # Enable log and config encryption
        # Not using encryption key for log encryption because we want
        # be able to remove that key after the test in this case then
        # (logs don't support re-encryption currently)
        set_log_encryption(self.cluster, 'nodeSecretManager', -1)
        set_cfg_encryption(self.cluster, 'encryptionKey', secret_id)

        # Load sample bucket with encryption enabled
        self.load_and_assert_sample_bucket(self.cluster, self.sample_bucket)
        self.cluster.update_bucket({
            'name': self.sample_bucket,
            'encryptionAtRestKeyId': secret_id
        })

        # Get a KV node to remove
        kv_nodes = [n for n in self.cluster.connected_nodes
                    if Service.KV in n.get_services()]
        candidate_for_removal = kv_nodes[0]
        return (candidate_for_removal, secret_id)

    def modify_encryption_for_node_readd_testing(self, node, prev_secret_id):
        secret = auto_generated_secret(
            usage=['bucket-encryption', 'config-encryption']
        )
        node = self.cluster.connected_nodes[0]
        new_secret_id = create_secret(node, secret)
        set_cfg_encryption(node, 'encryptionKey', new_secret_id)
        self.cluster.update_bucket({
            'name': self.sample_bucket,
            'encryptionAtRestKeyId': new_secret_id
        })
        # Deleting old secret, so all keys that not maintained properly should
        # become not decryptable
        # Need polling because bucket reencryption takes some time and should
        # happen on all nodes, and delete_secret will only work when there is no
        # bucket DEKs encrypted with that secret
        testlib.poll_for_condition(
            lambda: delete_secret(self.random_node(), prev_secret_id),
            sleep_time=1, attempts=50, retry_on_assert=True, verbose=True)

    def node_readd_test(self):
        node_to_remove, secret_id = \
            self.prepare_cluster_for_node_readd_testing()
        original_services = node_to_remove.get_services()

        # Remove the node
        self.cluster.rebalance(ejected_nodes=[node_to_remove], wait=True,
                               verbose=True)
        self.cluster.wait_nodes_up(verbose=True)

        # When node is removed, it's config gets wiped out
        set_min_timer_interval(node_to_remove, min_timer_interval)

        # Node has left the cluster, but it still contains the bucket data
        # directory which will be removed only during rebalance
        # Make sure DEKs in that bucket directory doesn't obstruct encryption
        # at rest reconfiguration
        drop_config_deks_for_node(node_to_remove)
        drop_bucket_deks_and_verify_dek_info(self.cluster, self.sample_bucket)
        # node_to_remove should continue having 1 dek, drop deks should
        # not affect it
        poll_verify_bucket_deks_files(
            [node_to_remove],
            self.sample_bucket,
            verify_key_count=1)

        # Add the node back
        self.cluster.add_node(node_to_remove, services=original_services,
                              verbose=True)

        self.modify_encryption_for_node_readd_testing(node_to_remove, secret_id)
        # Node is added back, and it still contains the bucket data directory
        # (it will be removed only during rebalance)
        # Try rotating config encryption DEK here to make sure those bucket
        # DEKs do not obstruct config DEK rotation
        drop_config_deks_for_node(node_to_remove)
        poll_verify_node_bucket_dek_info(node_to_remove, self.sample_bucket,
                                         missing=True)
        drop_bucket_deks_and_verify_dek_info(self.cluster, self.sample_bucket)

        # Rebalance to complete node addition
        self.cluster.rebalance(wait=True, verbose=True)

    def restart_cluster_with_bad_secret_test(self):
        # When unavailable KEK is used for cfg encryption, cluster will
        # fail to start, but if that KEK hasn't been used yet, the cluster
        # should start successfully.
        # Basically this test verifies that problems with DEK reencryption
        # don't prevent cluster from starting. Config DEKs should be readable
        # and decryptable, this goes without saying.
        bad_secret = aws_test_secret(usage=['config-encryption'],
                                     should_work=False)
        bad_aws_secret_id = create_secret(self.random_node(), bad_secret)
        set_cfg_encryption(self.cluster, 'encryptionKey', bad_aws_secret_id)
        self.cluster.restart()

    def add_node_when_kek_is_unavailable_test(self):
        bad_secret = aws_test_secret(usage=['config-encryption'],
                                     should_work=False)
        bad_aws_secret_id = create_secret(self.random_node(), bad_secret)

        # Trying to use bad AWS secret for encryption
        # This node will keep trying to reencrypt DEKs, which is ok
        set_cfg_encryption(self.cluster, 'encryptionKey', bad_aws_secret_id)

        node_to_remove = self.cluster.connected_nodes[-1]
        original_services = node_to_remove.get_services()

        # Remove the node
        self.cluster.rebalance(ejected_nodes=[node_to_remove], wait=True,
                               verbose=True)
        # Cluster is using bad secret for encryption, and its DEKs can't be
        # reencrypted. However, when this node leaves the cluster, it stops
        # using cluster secrets, switches to encryption service (default), and
        # reencrypts its DEKs.
        self.cluster.wait_nodes_up(verbose=True)

        # When node is removed, it's config gets wiped out
        set_min_timer_interval(node_to_remove, min_timer_interval)

        # Add the node back
        # During addition, the new node should encrypt its DEKs using cluster
        # secrets, but it will fail because current secret for cfg is bad.
        r = self.cluster.add_node(node_to_remove, services=original_services,
                                  expected_code=400, verbose=True)
        self.cluster.wait_nodes_up(verbose=True)
        testlib.assert_in('Failed to reencrypt some encryption-at-rest keys',
                          r.text)

        # Don't use bad secret for cfg encryption anymore...
        set_cfg_encryption(self.cluster, 'nodeSecretManager', -1)
        # ... and try again, this time addition should succeed
        self.cluster.add_node(node_to_remove, services=original_services,
                              verbose=True)
        # Rebalance to complete node addition
        self.cluster.rebalance(wait=True, verbose=True)

    def node_failover_and_add_back_delta_test(self):
        self.node_failover_and_add_back_base(recovery_type="delta")

    def node_failover_and_add_back_full_test(self):
        self.node_failover_and_add_back_base(recovery_type="full")

    def node_failover_and_add_back_base(self, recovery_type=None):
        node_to_failover, secret_id = \
            self.prepare_cluster_for_node_readd_testing()

        self.cluster.failover_node(node_to_failover,
                                   graceful=False,
                                   allow_unsafe=False,
                                   verbose=True)
        self.modify_encryption_for_node_readd_testing(node_to_failover,
                                                      secret_id)
        drop_config_deks_for_node(node_to_failover)
        drop_bucket_deks_and_verify_dek_info(self.cluster, self.sample_bucket)
        # node_to_failover should have 2 deks now, because it can't drop
        # old dek, bucket is not created in memcached so it can't reencrypt
        # the data
        poll_verify_bucket_deks_files(
            [node_to_failover],
            self.sample_bucket,
            verify_key_count=2)

        self.cluster.set_recovery_type(node_to_failover,
                                       recovery_type=recovery_type,
                                       verbose=True)
        drop_config_deks_for_node(node_to_failover)
        drop_bucket_deks_and_verify_dek_info(self.cluster, self.sample_bucket)
        # for the same reason as above node should have 3 deks now
        poll_verify_bucket_deks_files(
            [node_to_failover],
            self.sample_bucket,
            verify_key_count=3)

        self.cluster.rebalance(wait=True, verbose=True)


    def drop_dek_test(self):
        self.load_and_assert_sample_bucket(self.cluster, self.sample_bucket)
        poll_verify_bucket_deks_files(self.cluster,
                                      self.sample_bucket,
                                      verify_key_count=0)
        secret_json = aws_test_secret(usage=['bucket-encryption'])
        aws_secret_id = create_secret(self.random_node(), secret_json)
        self.cluster.update_bucket({'name': self.sample_bucket,
                                    'encryptionAtRestKeyId': aws_secret_id})

        # Compaction is needed to make sure the dek is actually used
        # If first key is not actually used, the drop key procedure will have
        # nothing to do, and the first key can simply be removed in this case
        testlib.post_succ(self.cluster,
                          f'/pools/default/buckets/{self.sample_bucket}' \
                          '/controller/compactBucket')
        dek_ids = poll_verify_and_get_mcd_deks_in_use(self.cluster,
                                                      self.sample_bucket,
                                                      verify_key_count=1)
        # Sleep to make sure drop bucket time that is generated by
        # the drop keys endpoint is strictly greater than current dek's
        # creation time.
        # In other words if we generate dek and call /drop immediately after
        # that, that dek will be considered up to date, because its datetime
        # is >= drop keys datetime.
        time.sleep(1.1)

        drop_time = datetime.now(timezone.utc).replace(microsecond=0)
        # 'Drop key' should force encryption of the whole bucket
        drop_bucket_keys(self.random_node(), self.sample_bucket)

        new_dek_ids = assert_bucket_deks_have_changed(self.cluster,
                                                      self.sample_bucket,
                                                      verify_key_count=1,
                                                      min_time=drop_time,
                                                      old_dek_ids=dek_ids)

        # Sleeping for the same reason as above
        time.sleep(1.1)
        # call 'drop key' again, this time it should re-encrypt the data with
        # a new key. We can't verify that the data was re-encrypted but we can
        # check that deks changed
        drop_time = datetime.now(timezone.utc).replace(microsecond=0)
        drop_bucket_keys(self.random_node(), self.sample_bucket)

        assert_bucket_deks_have_changed(self.cluster,
                                        self.sample_bucket,
                                        verify_key_count=1,
                                        min_time=drop_time,
                                        old_dek_ids=new_dek_ids)

    def remove_old_deks_test(self):
        secret = auto_generated_secret(usage=['bucket-encryption'])
        secret_id = create_secret(self.random_node(), secret)
        kek_id = get_kek_id(self.random_node(), secret_id)

        create_time = datetime.now(timezone.utc).replace(microsecond=0)
        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestKeyId': secret_id},
                                   sync=True)
        # Memorize deks in use (there should one on each kv node)
        dek_ids = assert_bucket_deks_have_changed(self.cluster,
                                                  self.bucket_name,
                                                  verify_key_count=1,
                                                  min_time=create_time,
                                                  old_dek_ids=[])

        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestDekRotationInterval': 1})

        # Now it generates a dek every sec, but it won't have more than 2 deks
        # because we don't write any new data to the bucket, and we are not
        # running compactions, so there always should be two deks: the one that
        # was used to encrypt data (the very first dek), and the one that is
        # active now.
        poll_verify_bucket_deks_files(self.cluster, self.bucket_name,
                                      verify_key_count=lambda n: n >= 2)

        # Change dek lifetime to 1 second and wait...
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestDekLifetime': 1,
                                    'encryptionAtRestDekRotationInterval': 600})

        # Now the very first dek should expire and the system should start
        # a compaction in order to get rid of it
        time.sleep(2)

        assert_bucket_deks_have_changed(self.cluster,
                                        self.bucket_name,
                                        verify_key_count=1,
                                        min_time=create_time,
                                        old_dek_ids=dek_ids)

    def dek_reencryption_test(self):
        # reenable encryption using different secret
        # and check if old dek is the same and that it gets reencrypted
        secret1 = auto_generated_secret(usage=['bucket-encryption'])
        secret_id1 = create_secret(self.random_node(), secret1)
        kek_id1 = get_kek_id(self.random_node(), secret_id1)

        secret2 = auto_generated_secret(usage=['bucket-encryption'])
        secret_id2 = create_secret(self.random_node(), secret2)
        kek_id2 = get_kek_id(self.random_node(), secret_id2)

        create_time = datetime.now(timezone.utc).replace(microsecond=0)
        self.cluster.create_bucket({'name': self.bucket_name, 'ramQuota': 100,
                                    'encryptionAtRestKeyId': secret_id1},
                                   sync=True)
        # Memorize deks in use (there should one on each kv node)
        dek_ids1 = poll_verify_bucket_deks_and_collect_ids(
                     self.cluster,
                     self.bucket_name,
                     verify_key_count=1,
                     verify_encryption_kek=kek_id1)

        # Disable encryption for bucket
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestKeyId': -1})

        # Now, while encryption is disabled, dek should still exist (because
        # there were no compaction). Rotate kek and verify that dek gets
        # re-encrypted.
        rotate_secret(self.random_node(), secret_id1)
        new_kek_id1 = get_kek_id(self.random_node(), secret_id1)

        dek_ids2 = poll_verify_bucket_deks_and_collect_ids(
                     self.cluster,
                     self.bucket_name,
                     verify_key_count=1,
                     verify_encryption_kek=new_kek_id1)

        assert dek_ids2 == dek_ids1, \
               f'deks have changed, old deks: {dek_ids1}, new deks: {dek_ids2}'

        # Enabled encryption again, but use another secret this time and
        # verify that dek gets rotated
        self.cluster.update_bucket({'name': self.bucket_name,
                                    'encryptionAtRestKeyId': secret_id2})

        dek_ids3 = poll_verify_bucket_deks_and_collect_ids(
                     self.cluster,
                     self.bucket_name,
                     verify_key_count=1,
                     verify_encryption_kek=kek_id2)

        assert dek_ids3 == dek_ids1, \
               f'deks have changed, old deks: {dek_ids1}, new deks: {dek_ids3}'

    def encrypted_logs_test(self):
        set_log_encryption(self.cluster, 'nodeSecretManager', -1)
        testlib.poll_for_condition(
            lambda: assert_logs_encrypted(self.cluster),
            sleep_time=0.3, attempts=50, retry_on_assert=True, verbose=True)
        set_log_encryption(self.cluster, 'disabled', -1)
        testlib.poll_for_condition(
            lambda: assert_logs_unencrypted(self.cluster),
            sleep_time=0.3, attempts=50, retry_on_assert=True, verbose=True)

    def stored_keys_file_encrypted_test(self):
        # verify that tokens file is encrypted and that it can be decrypted
        # using standard tool (cbcat), which basically verifies that
        # "couchbase-file-encryption" is implemented correctly in gosecrets
        node = self.random_node()
        data_dir = node.data_path()
        tokens_file = Path(data_dir) / 'config' / 'stored_keys_tokens'
        assert_file_is_decryptable(node, tokens_file)

    def config_dat_is_encrypted_test(self):
        # verify that config data is encrypted and that it can be decrypted
        # using standard tool (cbcat), which basically verifies that
        # "couchbase-file-encryption" is implemented correctly in cbcrypto
        node = self.random_node()
        data_dir = node.data_path()
        config_data_file = Path(data_dir) / 'config' / 'config.dat'
        assert_file_is_decryptable(node, config_data_file)


# Set master password and restart the cluster
# Testing that we can decrypt deks when master password is set
# (testing all combinations of master_password and encryption here)
class NativeEncryptionNodeRestartTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes = 1,
                                           edition='Enterprise',
                                           buckets=[],
                                           balanced=True,
                                           test_generated_cluster=True)

    def setup(self):
        pass

    def teardown(self):
        set_log_encryption(self.cluster, 'disabled', -1)
        set_cfg_encryption(self.cluster, 'nodeSecretManager', -1)
        change_password(self.node(), password='')

    def encryption_on_with_master_password_set_test(self):
        set_log_encryption(self.cluster, 'nodeSecretManager', -1)
        set_cfg_encryption(self.cluster, 'nodeSecretManager', -1)
        password = change_password(self.node())
        self.cluster.restart(master_passwords={0: password})

    def encryption_on_master_password_is_not_set_test(self):
        set_log_encryption(self.cluster, 'nodeSecretManager', -1)
        set_cfg_encryption(self.cluster, 'nodeSecretManager', -1)
        change_password(self.node(), password='')
        self.cluster.restart()

    def encryption_off_master_password_is_set_test(self):
        set_log_encryption(self.cluster, 'disabled', -1)
        set_cfg_encryption(self.cluster, 'disabled', -1)
        password = change_password(self.node())
        self.cluster.restart(master_passwords={0: password})

    def encryption_off_master_password_is_not_set_test(self):
        set_log_encryption(self.cluster, 'disabled', -1)
        set_cfg_encryption(self.cluster, 'disabled', -1)
        change_password(self.node(), password='')
        self.cluster.restart()

    def node(self):
        return self.cluster.connected_nodes[0]


class NativeEncryptionPermissionsTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition='Enterprise')

    def setup(self):
        set_cfg_encryption(self.cluster, 'nodeSecretManager', -1)
        self.bucket_name = testlib.random_str(8)
        self.password = testlib.random_str(8)
        bucket_props = {'name': self.bucket_name,
                        'ramQuota': 100,
                        'encryptionAtRestKeyId': -1}
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
        cfg = 'config-encryption'
        sec = 'KEK-encryption'
        all_b = 'bucket-encryption'
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


def set_cfg_encryption(cluster, *args, **kwargs):
    return set_comp_encryption(cluster, 'config', *args, **kwargs)


def set_log_encryption(cluster, *args, **kwargs):
    return set_comp_encryption(cluster, 'log', *args, dek_lifetime=0, **kwargs)


def set_comp_encryption(cluster, component, mode, secret,
                        dek_lifetime=60*60*24*365, dek_rotation=60*60*24*30,
                        expected_code=200):
    testlib.post_succ(cluster,
                      f'/settings/security/encryptionAtRest/{component}',
                      json={'encryptionMethod': mode,
                            'encryptionKeyId': secret,
                            'dekLifetime': dek_lifetime,
                            'dekRotationInterval': dek_rotation},
                      expected_code=expected_code)
    if expected_code == 200:
        r = testlib.get_succ(cluster, '/settings/security/encryptionAtRest')
        r = r.json()
        testlib.assert_eq(r[component]['encryptionMethod'], mode)
        testlib.assert_eq(r[component]['encryptionKeyId'], secret)


def auto_generated_secret(name=None,
                          usage=None,
                          auto_rotation=False, rotation_interval=7,
                          next_rotation_time=None,
                          encrypt_with='nodeSecretManager',
                          encrypt_secret_id=None):
    if usage is None:
        usage = ['bucket-encryption', 'KEK-encryption']
    if name is None:
        name = f'Test secret {testlib.random_str(5)}'
    optional = {}
    if encrypt_secret_id is not None:
        optional['encryptWithKeyId'] = encrypt_secret_id
    if next_rotation_time is not None:
        optional['nextRotationTime'] = next_rotation_time
    return {'name': name,
            'type': 'auto-generated-aes-key-256',
            'usage': usage,
            'data': {'autoRotation': auto_rotation,
                     'rotationIntervalInDays': rotation_interval,
                     'encryptWith': encrypt_with, **optional}}

# This secret does not actually go to aws when asked encrypt or decrypt data.
# All AWS secrets with special ARN=TEST_AWS_KEY_ARN simply encrypt data using
# dummy key.
def aws_test_secret(name=None, usage=None, should_work=True):
    if usage is None:
        usage = ['bucket-encryption', 'KEK-encryption']
    if name is None:
        name = f'Test secret {testlib.random_str(5)}'

    if should_work:
        key_arn = 'TEST_AWS_KEY_ARN'
    else:
        key_arn = 'TEST_AWS_BAD_KEY_ARN'

    return {'name': name,
            'type': 'awskms-aes-key-256',
            'usage': usage,
            'data': {'keyARN': key_arn}}


def get_secret(cluster, secret_id, expected_code=200, auth=None):
    if auth is None:
        auth = cluster.auth
    r = testlib.get_succ(cluster, f'/settings/encryptionKeys/{secret_id}',
                         expected_code=expected_code, auth=auth)
    if expected_code == 200:
        return r.json()
    return r.text


def get_secrets(cluster, auth=None):
    if auth is None:
        auth = cluster.auth
    return testlib.get_succ(cluster, '/settings/encryptionKeys',
                            auth=auth).json()


def create_secret(cluster, json, expected_code=200, auth=None):
    if auth is None:
        auth = cluster.auth
    r = testlib.post_succ(cluster, '/settings/encryptionKeys', json=json,
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
    r = testlib.put_succ(cluster, f'/settings/encryptionKeys/{secret_id}',
                         json=json,
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
    testlib.delete(cluster, f'/settings/encryptionKeys/{secret_id}',
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
                path = Path(node.data_path()) / 'config' / 'keks'
                verify_key_file_by_id(path, key['id'], **kwargs)


def poll_verify_kek_files(*args, **kwargs):
    testlib.poll_for_condition(
      lambda: verify_kek_files(*args, **kwargs),
      sleep_time=0.3, attempts=50, retry_on_assert=True, verbose=True)


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
    if isinstance(cluster, list):
        nodes = cluster
    else:
        nodes = cluster.connected_nodes
    for node in nodes:
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
            if parse_key_file_name(path.name) is not None:
                c += 1
                print(f'Verifying dek {path.name}')
                verify_key_file(path, **kwargs)
            else:
                print(f'Skipping file {path} (doesn\'t seem to be a key file)')

        if verify_key_count is not None:
            print(f'dek count at {node}: {c}')
            if callable(verify_key_count):
                assert verify_key_count(c), f'dek count is unexpected: {c}'
            else:
                assert c == verify_key_count, f'dek count is unexpected: {c} ' \
                                              f'(expected: {verify_key_count})'

def verify_bucket_dek_info(node, bucket, missing=False, **kwargs):
    r = testlib.get(node, f'/pools/default/buckets/{bucket}')
    r = r.json()
    nodes = r['nodes']
    info = None
    for node in nodes:
        if 'thisNode' in node and node['thisNode']:
            info = node['bucketEncryptionAtRestInfo']
            break
    if missing:
        assert info is None, \
               f'bucketEncryptionAtRestInfo for bucket {bucket} ' \
               f'is present on node {node}'
    else:
        assert info is not None, \
               f'bucketEncryptionAtRestInfo for bucket {bucket} ' \
               f'is not present on node {node}'
    print(f'bucketEncryptionAtRestInfo for {bucket}: {info}')
    verify_dek_info(info, **kwargs)


def verify_node_dek_info(node, data_type, **kwargs):
    r = testlib.get_succ(node, '/nodes/self')
    r = r.json()
    info = r['encryptionAtRestInfo'][data_type]
    print(f'encryptionAtRestInfo for {data_type}: {info}')
    verify_dek_info(info, **kwargs)


def verify_dek_info(info, data_status=None, dek_number=None,
                    oldest_dek_time=None):
    if data_status is not None:
        assert 'dataStatus' in info, 'data status is not present in ' \
                                     'encryptionAtRestInfo'
        assert info['dataStatus'] == data_status, \
               f'data status is unexpected: {info["dataStatus"]}'
    if dek_number is not None:
        assert 'dekNumber' in info, 'dek number is not present in ' \
                                    'encryptionAtRestInfo'
        assert info['dekNumber'] == dek_number, \
               f'dek number is unexpected: {info["dekNumber"]}'
    if oldest_dek_time is not None:
        assert 'oldestDekCreationDatetime' in info, \
               'oldestDekCreationDatetime is not present in ' \
               'encryptionAtRestInfo'
        t = parse_iso8601(info['oldestDekCreationDatetime'])
        assert t >= oldest_dek_time, \
               f'dek time is unexpected: {t} (expected: {oldest_dek_time})'


def poll_verify_node_dek_info(*args, **kwargs):
    testlib.poll_for_condition(
      lambda: verify_node_dek_info(*args, **kwargs),
      sleep_time=1, attempts=120, retry_on_assert=True, verbose=True)


def poll_verify_node_bucket_dek_info(*args, **kwargs):
    testlib.poll_for_condition(
      lambda: verify_bucket_dek_info(*args, **kwargs),
      sleep_time=1, attempts=120, retry_on_assert=True, verbose=True)


def parse_key_file_name(base_name):
    tokens = base_name.split(".key.")
    if len(tokens) != 2:
        return None
    try:
        vsn = int(tokens[1])
    except:
        return None

    key_id = tokens[0]
    if not is_valid_key_id(key_id):
        return None
    return key_id


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
      sleep_time=1, attempts=15 + min_timer_interval,
      retry_on_assert=True, verbose=True)


def poll_verify_bucket_deks_and_collect_ids(*args, **kwargs):
    current_dek_ids = []

    def collect_ids(dek_id):
        current_dek_ids.append(dek_id)
        return True

    def verify():
        current_dek_ids.clear()
        verify_bucket_deks_files(verify_id=collect_ids, *args, **kwargs)

    testlib.poll_for_condition(
      verify, sleep_time=0.3, attempts=50, retry_on_assert=True, verbose=True)

    return current_dek_ids


def poll_verify_dek_files(*args, **kwargs):
    testlib.poll_for_condition(
      lambda: verify_dek_files(*args, **kwargs),
      sleep_time=0.3, attempts=50, retry_on_assert=True, verbose=True)


def verify_key_file_by_id(dir_path, key_id, verify_missing=False, **kwargs):
    files = list(dir_path.glob("./" + key_id + '.key.*'))
    if verify_missing:
        assert len(files) == 0, f'key files exists: {files}'
    else:
        assert len(files) == 1, f'more than one version found: {files}'
        verify_key_file(files[0])


def verify_key_file(path, verify_encryption_kek=None,
                    verify_creation_time=None, verify_id=None):
    assert path.is_file(), f'key file doesn\'t exist: {path}'
    content = json.loads(path.read_bytes())
    if verify_encryption_kek is not None:
        has_kek = content['keyData']['encryptionKeyName']
        assert has_kek == verify_encryption_kek, \
               f'key is encrypted by wrong kek {has_kek} ' \
               f'(expected: {verify_encryption_kek})'
    if verify_creation_time is not None:
        ct = content['keyData']['creationTime']
        assert verify_creation_time(parse_iso8601(ct)), \
               f'Unexpected key creation time: {ct} ' \
               f'(cur time: {datetime.now(timezone.utc)})'
    if verify_id is not None:
        key_id = parse_key_file_name(path.name)
        assert key_id is not None, f"invalid key filename: path.name"
        assert verify_id(key_id), f'unexpected key id: {key_id}'
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
                                                         '<<"ad">>,'
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
            '{ok, R} = encryption_service:decrypt_key(B, <<"ad">>, '
                                                    f'<<"{kek_id}">>),'
            '"Success:" ++ binary_to_list(R).')
    search_res = re.search('"Success:(.*)"', res.text)
    assert search_res is not None, f'unexpected decrypt result: {res.text}'
    return search_res.group(1)


def rotate_secret(cluster, secret_id):
    testlib.post_succ(cluster, f'/controller/rotateEncryptionKey/{secret_id}')


def poll_verify_deks_and_collect_ids(*args, **kwargs):
    current_dek_ids = []

    def collect_ids(dek_id):
        current_dek_ids.append(dek_id)
        return True

    def verify():
        current_dek_ids = []
        verify_dek_files(verify_id=collect_ids, *args, **kwargs)

    testlib.poll_for_condition(
      verify, sleep_time=0.3, attempts=50, retry_on_assert=True, verbose=True)

    print(f'key list extracted: {current_dek_ids}')

    return current_dek_ids


def set_cfg_dek_limit(cluster, n):
    key = '{cb_cluster_secrets, {max_dek_num, configDek}}'
    set_ns_config_value(cluster, key, n)


def set_bucket_dek_limit(cluster, bucket, n):
    key = '{cb_cluster_secrets, {max_dek_num, {bucketDek, "' + bucket + '"}}}'
    set_ns_config_value(cluster, key, n)


def set_min_timer_interval(cluster, n):
    set_ns_config_value(cluster, '{cb_cluster_secrets, min_timer_interval}', n)


def set_ns_config_value(cluster, key_str, value):
    if value is None:
        testlib.diag_eval(cluster, f'ns_config:delete({key_str}).')
    else:
        testlib.diag_eval(cluster, f'ns_config:set({key_str}, {value}).')


def parse_iso8601(s):
    # can't use datetime.fromisoformat because it doesn't parse UTC datetimes
    # before version 3.11
    return dateutil.parser.parse(s)

def drop_deks(cluster, data_type):
    testlib.post_succ(cluster,
                      f'/controller/dropEncryptionAtRestDeks/{data_type}')

def drop_bucket_keys(cluster, bucket):
    testlib.post_succ(cluster,
                      f'/controller/dropEncryptionAtRestDeks/bucket/{bucket}')

def poll_verify_and_get_mcd_deks_in_use(*args, **kwargs):
    return testlib.poll_for_condition(
             lambda: verify_and_get_mcd_deks_in_use(*args, **kwargs),
             sleep_time=0.3, attempts=50, retry_on_assert=True, verbose=True)

def verify_and_get_mcd_deks_in_use(cluster, bucket, verify_key_count=None):
    res = []
    for node in cluster.connected_nodes:
        if Service.KV not in node.get_services():
            continue
        deks = get_bucket_deks_in_use(node, bucket)
        if verify_key_count is not None:
            assert len(deks) == verify_key_count, \
                   f'unexpected number of deks, expected: {verify_key_count}, '\
                   f'got: {deks}'
        res.extend(deks)

    return res


def get_bucket_deks_in_use(node, bucket):
    r = testlib.diag_eval(node,
                          '{ok, L} = ns_memcached:get_dek_ids_in_use("' +
                          bucket + '"), {json, L}.')
    print(f'ns_memcached:get_dek_ids_in_use("{bucket}") for {node} '
          f'returned {r.text}')
    ids = json.loads(r.text)
    return [dek_id for dek_id in ids if dek_id != 'null_dek_id']


def assert_bucket_deks_have_changed(cluster, bucket, min_time=None,
                                    old_dek_ids=None, verify_key_count=None,
                                    **kwargs):
    # checking that bucket deks have changed
    poll_verify_bucket_deks_files(
      cluster,
      bucket,
      verify_key_count=verify_key_count,
      verify_creation_time=lambda ct: ct >= min_time,
      verify_id=lambda n: n not in old_dek_ids,
      **kwargs)

    # checking that bucket actually uses a dek
    dek_ids = poll_verify_and_get_mcd_deks_in_use(
                cluster, bucket, verify_key_count=verify_key_count)
    assert len(dek_ids) > 0, f'bucket deks are empty: {dek_ids}'
    # ... and checking that on disk we have the same dek and nothing else
    poll_verify_bucket_deks_files(cluster,
                                  bucket,
                                  verify_key_count=verify_key_count,
                                  verify_id=lambda n: n in dek_ids,
                                  **kwargs)

    return dek_ids


def assert_logs_encrypted(cluster):
    for n in cluster.connected_nodes:
        debug_log_path = Path(n.logs_path()) / 'debug.log'
        assert_file_encrypted(debug_log_path)


def assert_logs_unencrypted(cluster):
    for n in cluster.connected_nodes:
        debug_log_path = Path(n.logs_path()) / 'debug.log'
        assert_file_unencrypted(debug_log_path)


def assert_file_encrypted(path):
    print(f'Checking file {path} is encrypted')
    with open(path, 'rb') as f:
        magic_len = len(encrypted_file_magic)
        magic = f.read(magic_len)
        print(f'magic: {magic}')
        assert magic == encrypted_file_magic, \
               f'file {path} doesn\'t seem to be encrypted, ' \
               f'first {magic_len} bytes are {magic}'


def assert_file_unencrypted(path):
    print(f'Checking file {path} is unencrypted')
    assert path.is_file(), f'file doesn\'t exist: {path}'
    with open(path, 'rb') as f:
        magic_len = len(encrypted_file_magic)
        magic = f.read(magic_len)
        print(f'magic: {magic}')
        assert len(magic) == magic_len, \
               f'file is too short ({len(magic)} bytes read)'
        assert magic != encrypted_file_magic, \
               f'file {path} seems to be encrypted, ' \
               f'first {magic_len} bytes are {magic}'


def assert_file_is_decryptable(node, file_path):
    data_dir = node.data_path()
    assert_file_encrypted(file_path)
    gosecrets_cfg_path = Path(data_dir) / 'config' / 'gosecrets.cfg'
    cbcat_path = testlib.get_utility_path('cbcat')
    cbcat_args = ['--with-gosecrets', gosecrets_cfg_path, file_path]
    r = subprocess.run([cbcat_path] + cbcat_args, capture_output=True)
    assert r.returncode == 0, f'cbcat returned {r.returncode}\n' \
                                f'stdout: {r.stdout.decode()}\n' \
                                f'stderr: {r.stderr.decode()}'


def drop_config_deks_for_node(node):
    drop_time = datetime.now(timezone.utc).replace(microsecond=0)
    drop_deks(node, 'config')
    poll_verify_node_dek_info(node, 'configuration',
                              data_status='encrypted',
                              dek_number=1,
                              oldest_dek_time=drop_time)

def drop_bucket_deks_and_verify_dek_info(cluster, bucket):
    drop_time = datetime.now(timezone.utc).replace(microsecond=0)
    drop_bucket_keys(cluster, bucket)

    for node in cluster.connected_nodes:
        if node.get_cluster_membership() == 'active' and \
           Service.KV in node.get_services():
            poll_verify_node_bucket_dek_info(node, bucket,
                                             data_status='encrypted',
                                             dek_number=1,
                                             oldest_dek_time=drop_time)
        else:
            poll_verify_node_bucket_dek_info(node, bucket,
                                             missing=True)