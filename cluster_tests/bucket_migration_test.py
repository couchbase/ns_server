# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
import time

def get_bucket(cluster, bucket_name):
    return testlib.json_response(
        testlib.get_succ(cluster, f"/pools/default/buckets/{bucket_name}"),
        "non-json response for " + f"/pools/default/buckets/{bucket_name}")

def create_and_update_bucket(cluster, bucket_name, old_storage_mode,
                             new_storage_mode, ram_quota_mb):
    data = {'name': f'{bucket_name}',
            'storageBackend': f'{old_storage_mode}',
            'ramQuotaMB': f'{ram_quota_mb}'}
    cluster.create_bucket(data)

    def is_server_list_non_empty():
        res = get_bucket(cluster, bucket_name)
        return len(res['vBucketServerMap']['serverList']) != 0

    testlib.poll_for_condition(is_server_list_non_empty, sleep_time=0.25,
                               attempts=100, timeout=60,
                               msg="poll is server-list not empty")

    data['storageBackend'] = f'{new_storage_mode}'
    cluster.update_bucket(data)

def get_per_node_storage_mode(cluster, bucket_name):
    res = get_bucket(cluster, bucket_name)
    return {n['hostname']: n['storageBackend'] for n in res['nodes']
            if n.get('storageBackend') != None}

def assert_per_node_storage_mode_keys_added(cluster, bucket_name,
                                            expected_storage_mode):
    per_node_storage_mode = get_per_node_storage_mode(
        cluster, bucket_name)
    storage_modes = per_node_storage_mode.values()
    # Assert per-node storage_mode was added to all the nodes
    # and it's the expected_storage_mode.
    assert len(storage_modes) == len(cluster.connected_nodes) and \
        all([storage_mode == expected_storage_mode
             for storage_mode in storage_modes])

def assert_per_node_storage_mode_keys_deleted(cluster, node, bucket_name):
    per_node_storage_mode = get_per_node_storage_mode(
        cluster, bucket_name)
    assert None == per_node_storage_mode.get(node.hostname)

def assert_per_node_storage_mode_in_memcached(node, bucket_name,
                                              expected_storage_mode):
    diag_eval = f'ns_memcached:get_config_stats("{bucket_name}", <<"ep_backend">>).'
    res = testlib.post_succ(node, "/diag/eval", data=diag_eval)
    assert res.content.decode('ascii').strip("<<\"").strip("\">>") == expected_storage_mode

class BucketMigrationTest(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=4, memsize=2*1024,
                                           num_connected=2)

    def setup(self, cluster):
        testlib.delete_all_buckets(cluster)
        # We modify the couchbase_num_vbuckets_default key below - assert it
        # isn't currently already set to prevent unexpected behavior once it is
        # deleted in the teardown function below.
        curr_num_vbuckets = testlib.post_succ(
            cluster, "/diag/eval",
            data='ns_bucket:get_default_num_vbuckets()').content.decode('ascii')
        assert curr_num_vbuckets == "1024", "non-default num vbuckets set"

        # Set default num vbuckets for any bucket to 64 to reduce rebalance
        # times.
        diag_eval = f'ns_config:set(couchbase_num_vbuckets_default, 64)'
        testlib.post_succ(cluster, "/diag/eval", data=diag_eval)

    def teardown(self, cluster):
        testlib.delete_all_buckets(cluster)
        diag_eval = f'ns_config:delete(couchbase_num_vbuckets_default)'
        testlib.post_succ(cluster, "/diag/eval", data=diag_eval)

    def migrate_storage_mode_test(self, cluster):
        # couchstore -> magma migration.
        create_and_update_bucket(cluster, "bucket-1", "couchstore", "magma",
                                 1024)
        assert_per_node_storage_mode_keys_added(
            cluster, "bucket-1", "couchstore")

        cluster.delete_bucket("bucket-1")

        # magma -> couchstore migration
        create_and_update_bucket(cluster, "bucket-2", "magma", "couchstore",
                                 1024)
        assert_per_node_storage_mode_keys_added(cluster, "bucket-2", "magma")
        cluster.delete_bucket("bucket-2")

    def migrate_storage_mode_via_rebalance_test(self, cluster):
        # Delete buckets irrelevant to this test, to reduce the rebalance
        # completion times.
        testlib.delete_all_buckets(cluster)
        create_and_update_bucket(cluster, "bucket-1", "couchstore", "magma",
                                 1024)
        assert_per_node_storage_mode_keys_added(cluster, "bucket-1",
                                                "couchstore")

        old_nodes = cluster.nodes[0:2]

        for i, old_node in enumerate(old_nodes):
            new_node = cluster.nodes[2 + i]
            cluster.add_node(new_node, verbose=True)
            # Rebalance out the old node and confirm the per-node storage-mode
            # key is removed.
            cluster.rebalance(ejected_nodes=[old_node], wait=True,
                              verbose=True)

            assert_per_node_storage_mode_in_memcached(
                new_node, "bucket-1", "magma")
            assert_per_node_storage_mode_keys_deleted(
                cluster, new_node, "bucket-1")

    def migrate_storage_mode_via_failover_test(self, cluster):
        create_and_update_bucket(cluster, "bucket-2", "couchstore", "magma",
                                 1024)
        assert_per_node_storage_mode_keys_added(cluster, "bucket-2",
                                                "couchstore")
        nodes = cluster.connected_nodes
        for node in nodes:
            cluster.failover_node(node, graceful=False)
            cluster.recover_node(node, do_rebalance=True)

            assert_per_node_storage_mode_in_memcached(
                node, "bucket-2", "magma")
            assert_per_node_storage_mode_keys_deleted(
                cluster, node, "bucket-2")
