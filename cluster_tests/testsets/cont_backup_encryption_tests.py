# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import os
import time
import json
import shutil
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import testlib
from testlib.requirements import Service
from testsets.native_encryption_tests import \
    cb_managed_secret, create_secret, delete_secret, drop_bucket_keys, \
    get_bucket_deks_in_use, parse_key_file_name, set_min_timer_interval, \
    set_min_dek_gc_interval, set_dek_info_update_interval


class ContBackupEncryptionTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition='Enterprise',
                                           num_nodes=2,
                                           num_connected=1,
                                           include_services={
                                               'n0': [Service.KV]},
                                           buckets=[],
                                           num_vbuckets=16)

    def setup(self):
        set_min_timer_interval(self.cluster, 1)
        set_min_dek_gc_interval(self.cluster, 2)
        set_dek_info_update_interval(self.cluster, 3)
        self.secret_id = create_secret(
            self.cluster, cb_managed_secret(usage=['bucket-encryption']))

    def teardown(self):
        delete_secret(self.cluster, self.secret_id)
        set_dek_info_update_interval(self.cluster, None)
        set_min_dek_gc_interval(self.cluster, None)
        set_min_timer_interval(self.cluster, None)

    def test_teardown(self):
        for b in self.cluster.get_buckets():
            self.cluster.delete_bucket(b['name'])

    # Backup generations that are still on disk can be the only users of a
    # dek (e.g. after the dek has been dropped and the data has been
    # re-encrypted by compaction). Such dek must be kept until continuous
    # backup uploads (and removes) the generations.
    def dek_kept_until_backup_files_uploaded_test(self):
        node = self.cluster.connected_nodes[0]
        bucket = 'contbk_' + testlib.random_str(6)
        dest = Path(node.tmp_path()) / f'contbk_dest_{testlib.random_str(6)}'
        dest.mkdir(parents=True)

        vault = start_vault_transit_mock()

        try:
            self.cluster.create_bucket(
                {'name': bucket,
                 'storageBackend': 'magma',
                 'ramQuota': 256,
                 'historyRetentionSeconds': 900,
                 'historyRetentionBytes': 2147483649,
                 'continuousBackupEnabled': 'true',
                 'continuousBackupInterval': '2',
                 'continuousBackupLocation': str(dest),
                 'continuousBackupRetentionPeriod': '1'},
                sync=True)
            bucket_uuid = self.cluster.get_bucket_uuid(bucket)

            # An encrypted bucket with continuous backup needs a KMS for the
            # backup's own keys, and REST validation only accepts cloud KMSs
            # (it tries to use them). So we set up encryption and point
            # backup to a local HashiCorp Vault mock bypassing the validation.
            km_url = f'hashivault://127.0.0.1:{vault.server_port}/testkey'
            testlib.diag_eval(
                node,
                f'{{ok, C}} = ns_bucket:get_bucket("{bucket}"), '
                f'E = proplists:get_value(extra_params, C), '
                f'ns_bucket:update_bucket_props("{bucket}", '
                f'[{{extra_params, E ++ [{{<<"continuous_backup_km_key_url">>,'
                f' <<"{km_url}">>}}]}}, '
                f'{{encryption_secret_id, {self.secret_id}}}]).')

            load_docs(self.cluster, bucket, 'a', 100)

            old_deks = poll_mcd_deks(self.cluster, node, bucket, 1)
            old_dek = old_deks[0]
            print(f'Old dek: {old_dek}')

            # Initial generations should be uploaded and removed
            testlib.poll_for_condition(
                lambda: any(dest.iterdir()) and
                        backup_generations(node, bucket_uuid) == [],
                sleep_time=1, timeout=120,
                msg='wait for initial backup to be uploaded')

            # Make the destination read-only, so new generations can't be
            # uploaded and stay on disk
            set_tree_writable(dest, False)

            load_docs(self.cluster, bucket, 'b', 100)
            gens = testlib.poll_for_condition(
                lambda: backup_generations(node, bucket_uuid) or False,
                sleep_time=2, timeout=200,
                msg='wait for a generation to get stuck on disk')
            print(f'Stuck generations: {gens}')

            backup_ids = cont_backup_deks_in_use(node, bucket_uuid)
            assert old_dek in backup_ids, \
                   f'{old_dek} is not reported by backup: {backup_ids}'

            # Drop keys makes memcached re-encrypt all data with a new dek
            drop_bucket_keys(self.cluster, bucket)

            def mcd_stopped_using_old_dek():
                ids = get_bucket_deks_in_use(self.cluster, node, bucket)
                return len(ids) > 0 and old_dek not in ids

            testlib.poll_for_condition(
                mcd_stopped_using_old_dek, sleep_time=1, timeout=120,
                msg='wait for memcached to stop using old dek')

            # Give GC several attempts to remove the old dek. It must stay
            # because backup still reports it.
            for _ in range(10):
                assert backup_generations(node, bucket_uuid) != [], \
                       'generation has disappeared (test prerequisite)'
                assert old_dek in bucket_dek_ids_on_disk(node, bucket_uuid), \
                       f'{old_dek} was removed while still used by backup'
                assert old_dek in cont_backup_deks_in_use(node, bucket_uuid)
                time.sleep(2)

            # Allow backup to upload the generations. The old dek should
            # disappear after that.
            set_tree_writable(dest, True)

            testlib.poll_for_condition(
                lambda: backup_generations(node, bucket_uuid) == [],
                sleep_time=1, timeout=120,
                msg='wait for stuck generations to be uploaded')

            # Magma keeps the old dek pinned until it notices that the
            # generation is gone, which it only does when it runs a backup.
            # It runs a backup only if it has new tables queued, so keep
            # writing (to all vbuckets) to trigger a backup every interval.
            def old_dek_removed():
                load_docs(self.cluster, bucket, 'c', 50)
                return old_dek not in bucket_dek_ids_on_disk(node,
                                                             bucket_uuid)

            testlib.poll_for_condition(
                old_dek_removed, sleep_time=5, timeout=300,
                msg='wait for old dek to be removed')

            assert_no_unknown_dek_errors(node)
        finally:
            set_tree_writable(dest, True)
            testlib.ensure_deleted(self.cluster,
                                   f'/pools/default/buckets/{bucket}')
            shutil.rmtree(dest, ignore_errors=True)
            vault.shutdown()
            vault.server_close()

    # Backup files left from a previous cluster membership are useless (their
    # deks are gone), so they are removed when a node joins or leaves.
    def backup_dir_removed_on_join_and_leave_test(self):
        new_node = self.cluster.spare_node()
        stale = Path(new_node.dbdir()) / '@continuous_backup' / \
            uuid.uuid4().hex / '0' / '1' / '1'
        stale.mkdir(parents=True)
        (stale / 'metadata').write_text('stale')

        self.cluster.add_node(new_node, services=[Service.KV])
        try:
            assert not stale.parent.parent.parent.exists(), \
                   f'{stale} has not been removed on join'

            self.cluster.rebalance()
            stale.mkdir(parents=True)
            (stale / 'metadata').write_text('stale')
        finally:
            self.cluster.rebalance(ejected_nodes=[new_node])

        testlib.poll_for_condition(
            lambda: not stale.parent.parent.parent.exists(),
            sleep_time=1, timeout=60,
            msg='wait for backup dir to be removed on leave')


def load_docs(cluster, bucket, prefix, n):
    for i in range(n):
        testlib.post_succ(cluster,
                          f'/pools/default/buckets/{bucket}/docs/{prefix}{i}',
                          data={'value': json.dumps({'v': i})})


def poll_mcd_deks(cluster, node, bucket, count):
    def f():
        ids = get_bucket_deks_in_use(cluster, node, bucket)
        assert len(ids) == count, f'unexpected deks in use: {ids}'
        return ids
    return testlib.poll_for_condition(f, sleep_time=1, timeout=60,
                                      retry_on_assert=True)


def backup_generations(node, bucket_uuid):
    root = Path(node.dbdir()) / '@continuous_backup' / bucket_uuid
    return sorted(str(p) for p in root.glob('*/*/*')
                  if (p / 'metadata').exists())


def cont_backup_deks_in_use(node, bucket_uuid):
    r = testlib.diag_eval(
          node,
          f'S = chronicle_compat:get_snapshot('
          f'[fun cb_cluster_secrets:fetch_snapshot_in_txn/1], #{{}}), '
          f'{{ok, L}} = cb_deks_cbauth:get_dek_ids_in_use('
          f'{{bucketDek, <<"{bucket_uuid}">>}}, S), '
          f'{{json, L}}.')
    ids = json.loads(r.text)
    print(f'Backup reports deks in use: {ids}')
    return ids


def bucket_dek_ids_on_disk(node, bucket_uuid):
    deks_path = Path(node.data_path()) / 'data' / bucket_uuid / 'deks'
    ids = [parse_key_file_name(p.name) for p in deks_path.iterdir()]
    return [i for i in ids if i is not None]


def set_tree_writable(path, writable):
    mode = 0o755 if writable else 0o555
    for root, dirs, _ in os.walk(path):
        for d in dirs:
            os.chmod(os.path.join(root, d), mode)
    os.chmod(path, mode)


def assert_no_unknown_dek_errors(node):
    log = Path(node.logs_path()) / 'cont_backup.log'
    if not log.exists():
        return
    text = log.read_text(errors='replace')
    assert 'has a DEK we do not know about' not in text and \
           'encrypted with unknown key' not in text, \
           'backup failed to find a dek'


class VaultTransitMockHandler(BaseHTTPRequestHandler):
    """Minimal HashiCorp Vault transit engine: 'encrypts' data by prefixing
    it, which is enough for continuous backup to wrap its keys."""
    prefix = 'vault:v1:'

    def do_PUT(self):
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length) or b'{}')
        # /v1/transit/(encrypt|decrypt)/<key>
        op = self.path.strip('/').split('/')[2]
        if op == 'encrypt':
            data = {'ciphertext': self.prefix + body['plaintext']}
        else:
            data = {'plaintext': body['ciphertext'][len(self.prefix):]}
        resp = json.dumps({'data': data}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    do_POST = do_PUT

    def log_message(self, *args):
        pass


def start_vault_transit_mock():
    server = ThreadingHTTPServer(('127.0.0.1', 0), VaultTransitMockHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server
