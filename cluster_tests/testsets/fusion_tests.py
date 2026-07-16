# @author Couchbase <info@couchbase.com>
# @copyright 2025 Couchbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import testlib
import glob
import json
import os
import shutil
import random
import re
import subprocess

from testlib import ClusterRequirements
from testlib.util import Service

from testsets.config_remap_tests import ConfigRemapTest

class FusionTests(testlib.BaseTestSet):

    def setup(self):
        node = self.cluster.connected_nodes[0]
        logstore_dir = node.tmp_path() + '/logstore'
        backup_dir = node.tmp_path() + '/backup'

        if not os.path.exists(logstore_dir):
            os.makedirs(logstore_dir)

        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)

        self.cluster.logstore_dir = logstore_dir
        self.cluster.backup_dir = backup_dir

        # prep_restore overrides fusion_sync_rate_limit (a cluster-wide
        # memcached global) to 0 to freeze the LogStore. Capture the baseline
        # effective value now so test_teardown can restore it -- otherwise the
        # override leaks into subsequent tests, whose syncLogStore then uploads
        # nothing and the accelerator generates an empty manifest.
        eff = testlib.get_succ(
            self.cluster,
            f"/pools/default/settings/memcached/effective/{node.otp_node()}"
            ).json()
        self.default_fusion_sync_rate_limit = eff['fusion_sync_rate_limit']

    def teardown(self):
        if not os.path.exists(self.cluster.logstore_dir):
            shutil.rmtree(self.cluster.logstore_dir)

    def test_teardown(self):
        testlib.delete_all_buckets(self.cluster)

        # Rebalance the cluster and remove all but one node
        self.cluster.rebalance(self.cluster.connected_nodes[1:], wait=True,
                               verbose=True)
        self.cluster.wait_nodes_up()
        testlib.diag_eval(self.cluster,
                          'chronicle_kv:delete(kv, fusion_config).')
        testlib.diag_eval(self.cluster,
                          'chronicle_kv:delete(kv, fusion_storage_snapshots).')
        testlib.testconditions_clear(self.cluster)

        # prep_restore sets fusion_sync_rate_limit to 0 to freeze the LogStore.
        # It's a cluster-wide memcached global that persists across tests, so
        # restore the baseline captured in setup(); otherwise a subsequent
        # test's syncLogStore uploads nothing and the accelerator generates an
        # empty manifest.
        testlib.post_succ(
            self.cluster, "/pools/default/settings/memcached/global",
            data={'fusion_sync_rate_limit':
                  self.default_fusion_sync_rate_limit},
            expected_code=202)

        for d in [self.cluster.logstore_dir, self.cluster.backup_dir]:
            shutil.rmtree(d)
            os.makedirs(d)

    @staticmethod
    def requirements():
        return [ClusterRequirements(edition="Enterprise",
                                    memsize=1024,
                                    include_services=[Service.KV],
                                    min_num_nodes=3, num_connected=1,
                                    num_vbuckets=16, buckets=[])]

    def get_status(self):
        resp = testlib.get_succ(self.cluster, '/fusion/status')
        status = resp.json()
        assert isinstance(status, dict)
        return status

    def assert_state(self, expected):
        assert self.get_status()['state'] == expected

    def wait_for_state(self, intermediate, final):
        def got_state():
            status = self.get_status()
            if status['state'] == final:
                return True
            else:
                assert status['state'] == intermediate
                return False

        testlib.poll_for_condition(got_state, 1, attempts=60,
                                   msg=f"Wait for state to become {final}")

    def assert_bucket_state(self, name, expected):
        bucket = self.cluster.get_bucket(name)
        if expected == 'disabled':
            assert 'fusionState' not in bucket
        else:
            assert bucket['fusionState'] == expected

    def empty_bucket_1_replica_smoke_test(self):
        self.empty_bucket_smoke_test_code(1, 16)

    def empty_bucket_0_replicas_smoke_test(self):
        self.empty_bucket_smoke_test_code(0, 8)

    def init_fusion(self):
        self.assert_state('disabled')
        testlib.post_succ(
            self.cluster, '/settings/fusion',
            json={'logStoreURI': 'local://' + self.cluster.logstore_dir,
                  'enableSyncThresholdMB': 1024})

    def create_bucket(self, name, num_replicas, overrides = {},
                      expected_code=202):
        return self.cluster.create_bucket(
            {'name': name, 'ramQuota': 100, 'bucketType': 'membase',
             'storageBackend': 'magma', 'flushEnabled' : 1,
             'replicaNumber': num_replicas} | overrides,
            sync=True, expected_code=expected_code)

    def prepare_rebalance(self, keep_nodes):
        keep_nodes_string = ",".join(keep_nodes)

        resp = testlib.post_succ(self.cluster,
                                 "/controller/fusion/prepareRebalance",
                                 data={'keepNodes': keep_nodes_string,
                                       'snapshotLifetimeSec': 300})
        acc_plan = resp.json()
        assert isinstance(acc_plan, dict)
        assert "planUUID" in acc_plan
        assert "nodes" in acc_plan
        assert "logicalSize" in acc_plan
        assert "storageSize" in acc_plan

        plan_nodes = acc_plan["nodes"]
        assert isinstance(plan_nodes, dict)

        total_logical_size = 0
        total_storage_size = 0

        for vbucket_list in plan_nodes.values():
            for vbucket_info in vbucket_list:
                assert "logicalSize" in vbucket_info
                assert "storageSize" in vbucket_info
                total_logical_size += vbucket_info["logicalSize"]
                total_storage_size += vbucket_info["storageSize"]

        assert total_logical_size == acc_plan["logicalSize"]
        assert total_storage_size == acc_plan["storageSize"]

        return acc_plan

    def empty_bucket_smoke_test_code(self, num_replicas, expected_num_volumes):
        self.init_fusion()

        otp_nodes = testlib.get_otp_nodes(self.cluster)
        testlib.post_fail(self.cluster,
                          "/controller/fusion/prepareRebalance",
                          data={'keepNodes': otp_nodes.values()},
                          expected_code=412)

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        second_node = self.cluster.spare_node()
        self.create_bucket('test', num_replicas)

        self.cluster.add_node(second_node, services=[Service.KV])

        otp_nodes = testlib.get_otp_nodes(self.cluster)
        second_otp_node = otp_nodes[second_node.hostname()]

        testlib.post_fail(self.cluster, "/controller/fusion/prepareRebalance",
                          expected_code=400)

        acc_plan = self.prepare_rebalance(otp_nodes.values())
        plan_uuid = acc_plan["planUUID"]
        plan_nodes = acc_plan["nodes"]

        assert len(plan_nodes) == 1
        assert second_otp_node in plan_nodes
        volumes = plan_nodes[second_otp_node]
        len_volumes = len(volumes)
        assert len_volumes == expected_num_volumes

        # not enough nodes
        resp = testlib.post_fail(
            self.cluster,
            f"/controller/fusion/uploadMountedVolumes?planUUID={plan_uuid}",
            expected_code=400,
            json=generate_nodes_volumes(["n34@wrong"]))

        assert_json_error(resp.json(), "nodes", "Absent nodes")

        # too many nodes
        resp = testlib.post_fail(
            self.cluster,
            f"/controller/fusion/uploadMountedVolumes?planUUID={plan_uuid}",
            expected_code=400,
            json=generate_nodes_volumes(otp_nodes.values()))

        assert_json_error(resp.json(), "nodes", "Unneeded nodes")

        correct_nodes = [second_otp_node]

        # wrong planUUID
        resp = testlib.post_fail(
            self.cluster,
            f"/controller/fusion/uploadMountedVolumes?planUUID=12345",
            expected_code=400,
            json=generate_nodes_volumes(correct_nodes))

        assert_json_error(resp.json(),
                          "planUUID", "Doesn't match stored plan id")

        # success
        resp = testlib.post_succ(
            self.cluster,
            f"/controller/fusion/uploadMountedVolumes?planUUID={plan_uuid}",
            json=generate_nodes_volumes(correct_nodes))

        self.cluster.rebalance(plan_uuid = plan_uuid)

        self.check_uploaders('test')

        testlib.post_succ(self.cluster, "/controller/fusion/syncLogStore")

        resp = testlib.get_succ(self.cluster, "/fusion/activeGuestVolumes")
        volumes = resp.json()

        for node in otp_nodes.values():
            assert node in volumes

    def empty_volumes_smoke_test(self):
        self.init_fusion()
        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        second_node = self.cluster.spare_node()
        self.create_bucket('test', 1)

        self.cluster.add_node(second_node, services=[Service.KV])

        otp_nodes = testlib.get_otp_nodes(self.cluster)
        second_otp_node = otp_nodes[second_node.hostname()]

        acc_plan = self.prepare_rebalance(otp_nodes.values())
        plan_uuid = acc_plan["planUUID"]

        nodes_volumes_json = {'nodes': [{'name': second_otp_node,
                                         'guestVolumePaths': []}]}

        # success
        resp = testlib.post_succ(
            self.cluster,
            f"/controller/fusion/uploadMountedVolumes?planUUID={plan_uuid}",
            json=nodes_volumes_json)

        self.cluster.rebalance(plan_uuid = plan_uuid)

        self.check_uploaders('test')

        resp = testlib.get_succ(self.cluster, "/fusion/activeGuestVolumes")
        volumes = resp.json()
        assert volumes[second_otp_node] == []

    def bucket_flush_smoke_test(self):
        self.init_fusion()
        self.create_bucket('test', 1)
        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        testlib.post_succ(
            self.cluster,
            f"/pools/default/buckets/test/controller/doFlush")

    def sync_log_store_test(self):
        url = "/controller/fusion/syncLogStore"

        # Create the bucket before enabling fusion so that it becomes a
        # fusion bucket once fusion is enabled.
        self.init_fusion()
        self.create_bucket('test', 1)
        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')
        self.assert_bucket_state('test', 'enabled')

        # ---- Query string parameter validation ----
        # timeout must be an integer in range 1..300000
        testlib.post_fail(self.cluster, url + "?timeout=0", expected_code=400)
        testlib.post_fail(self.cluster, url + "?timeout=300001",
                          expected_code=400)
        testlib.post_fail(self.cluster, url + "?timeout=abc",
                          expected_code=400)
        # reset must be a boolean
        testlib.post_fail(self.cluster, url + "?reset=maybe",
                          expected_code=400)
        # unsupported query string parameter
        testlib.post_fail(self.cluster, url + "?something=1",
                          expected_code=400)

        # ---- Case 1: no body -> sync all fusion buckets ----
        testlib.post_succ(self.cluster, url)
        # valid query string parameters are accepted
        testlib.post_succ(self.cluster, url + "?timeout=120000&reset=false")

        # ---- Body validation (must be a json object) ----
        resp = testlib.post_fail(self.cluster, url, data="not json",
                                 expected_code=400)
        assert_json_error(resp.json(), "_", "Invalid Json")
        resp = testlib.post_fail(self.cluster, url, json=[1, 2, 3],
                                 expected_code=400)
        assert_json_error(resp.json(), "_", "Invalid Json")

        # "buckets" is required
        resp = testlib.post_fail(self.cluster, url, json={}, expected_code=400)
        assert_json_error(resp.json(), "buckets", "The value must be supplied")
        # unsupported top level key
        resp = testlib.post_fail(
            self.cluster, url,
            json={'buckets': [{'name': 'test'}], 'bogus': 1},
            expected_code=400)
        assert_json_error(resp.json(), "bogus", "Unsupported key")
        # "buckets" must be a json array
        resp = testlib.post_fail(self.cluster, url, json={'buckets': 'test'},
                                 expected_code=400)
        assert_json_error(resp.json(), "buckets",
                          "The value must be a json array")

        # ---- Case 2: buckets without vbuckets ----
        # bucket "name" is required
        resp = testlib.post_fail(self.cluster, url, json={'buckets': [{}]},
                                 expected_code=400)
        assert_bucket_error(resp.json(), 0, "name",
                            "The value must be supplied")
        # "name" must be a string
        resp = testlib.post_fail(self.cluster, url,
                                 json={'buckets': [{'name': 123}]},
                                 expected_code=400)
        assert_bucket_error(resp.json(), 0, "name", "Value must be json string")
        # unknown bucket is not a fusion bucket
        resp = testlib.post_fail(self.cluster, url,
                                 json={'buckets': [{'name': 'unknown'}]},
                                 expected_code=400)
        assert_bucket_error(resp.json(), 0, "name",
                            'Bucket "unknown" is not a fusion bucket')
        # unsupported per-bucket key
        resp = testlib.post_fail(
            self.cluster, url,
            json={'buckets': [{'name': 'test', 'bogus': 1}]},
            expected_code=400)
        assert_bucket_error(resp.json(), 0, "bogus", "Unsupported key")
        # success
        testlib.post_succ(self.cluster, url,
                          json={'buckets': [{'name': 'test'}]})

        # ---- Case 3: buckets with vbuckets ----
        # vbuckets must not be empty
        resp = testlib.post_fail(
            self.cluster, url,
            json={'buckets': [{'name': 'test', 'vbuckets': []}]},
            expected_code=400)
        assert_bucket_error(
            resp.json(), 0, "vbuckets",
            "Length (0) must be in the range from 1 to infinity, inclusive")
        # vbuckets must be a json array
        resp = testlib.post_fail(
            self.cluster, url,
            json={'buckets': [{'name': 'test', 'vbuckets': 'foo'}]},
            expected_code=400)
        assert_bucket_error(resp.json(), 0, "vbuckets", "Must be an array")
        # vbuckets must be integers
        resp = testlib.post_fail(
            self.cluster, url,
            json={'buckets': [{'name': 'test', 'vbuckets': ['a']}]},
            expected_code=400)
        assert_bucket_error(resp.json(), 0, "vbuckets",
                            "Must be an array of integers")
        # vbucket out of range (cluster has 16 vbuckets: 0..15)
        resp = testlib.post_fail(
            self.cluster, url,
            json={'buckets': [{'name': 'test', 'vbuckets': [16]}]},
            expected_code=400)
        assert_bucket_error(resp.json(), 0, "vbuckets",
                            "16 - must be in range 0..15")
        # negative vbucket is out of range
        resp = testlib.post_fail(
            self.cluster, url,
            json={'buckets': [{'name': 'test', 'vbuckets': [-1]}]},
            expected_code=400)
        assert_bucket_error(resp.json(), 0, "vbuckets",
                            "-1 - must be in range 0..15")
        # success
        testlib.post_succ(
            self.cluster, url,
            json={'buckets': [{'name': 'test', 'vbuckets': [0, 1, 2]}]})

    def initial_configuration_test(self):
        testlib.post_fail(self.cluster, '/fusion/enable', expected_code=503)
        self.assert_state('disabled')
        testlib.get_fail(self.cluster, '/settings/fusion', expected_code=404)
        testlib.post_fail(self.cluster, '/settings/fusion', expected_code=400,
                          json={}),
        testlib.post_fail(self.cluster, '/settings/fusion', expected_code=400,
                          json={'something': 'something'}),
        testlib.post_fail(self.cluster, '/settings/fusion', expected_code=400,
                          json={'logStoreURI': 'http://something'}),
        testlib.post_succ(self.cluster, '/settings/fusion',
                          json={'logStoreURI': 's3://something'}),
        testlib.post_succ(self.cluster, '/settings/fusion',
                          json={'logStoreURI': 's3://something/else'}),
        resp = testlib.get_succ(self.cluster, '/settings/fusion')
        config = resp.json()
        assert config == {'logStoreURI': 's3://something/else',
                          'enableSyncThresholdMB': 1024 * 45}
        testlib.post_fail(self.cluster, '/settings/fusion', expected_code=400,
                          json={'enableSyncThresholdMB': 'something'}),
        testlib.post_fail(self.cluster, '/settings/fusion', expected_code=400,
                          json={'enableSyncThresholdMB': 10}),
        testlib.post_fail(self.cluster, '/settings/fusion', expected_code=400,
                          json={'enableSyncThresholdMB': 1024 * 1024 * 11}),
        testlib.post_succ(self.cluster, '/settings/fusion',
                          json={'logStoreURI': 's3://something',
                                'enableSyncThresholdMB': 5000}),
        resp = testlib.get_succ(self.cluster, '/settings/fusion')
        config = resp.json()
        assert config == {'logStoreURI': 's3://something',
                          'enableSyncThresholdMB': 5000}

        self.assert_state('disabled')

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.assert_state('enabling')

        testlib.post_fail(self.cluster, '/fusion/enable', expected_code=503)

    def get_backup_bucket_params(self):
        return {'continuousBackupEnabled': 'true',
                'continuousBackupLocation': self.cluster.backup_dir,
                'historyRetentionSeconds': 900,
                'historyRetentionBytes': 2147483649}

    def get_encryption_bucket_params(self):
        return {'encryptionAtRestKeyId': 0,
                'encryptionAtRestDekRotationInterval': 2592000,
                'encryptionAtRestDekLifetime': 31536000}

    def enabling_fusion_for_buckets_errors_test(self):
        self.create_bucket('magma', 1)
        self.create_bucket('couchstore', 1, {'bucketType': 'membase',
                                             'storageBackend': 'couchstore'})
        self.create_bucket('PiTR', 1, self.get_backup_bucket_params())
        resp = testlib.post_fail(self.cluster, '/fusion/enable',
                                 expected_code=400)

        assert_buckets_error(resp.json(),
                             {'PiTR': 'bucket with continuous backup enabled'})

        resp = testlib.post_fail(
            self.cluster, '/fusion/enable',
            data={'buckets': 'unknown,couchstore,magma,PiTR'},
            expected_code=400)

        assert_buckets_error(resp.json(),
                             {'PiTR': 'bucket with continuous backup enabled',
                              'unknown': 'not found',
                              'couchstore': 'not a Magma bucket'})

    def mutually_exclusive_bucket_params_test(self):
        self.init_fusion()
        self.create_bucket('test', 1, self.get_backup_bucket_params())
        self.cluster.delete_bucket('test')

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        params_to_test = [('continuousBackupEnabled',
                           self.get_backup_bucket_params()),
                          ('encryptionAtRestKeyId',
                           self.get_encryption_bucket_params())]

        for key, params in params_to_test:
            resp = self.create_bucket('test', 1, params, expected_code=400)
            get_json_error(resp.json(), key)

            ## encryption is disallowed even on non fusion buckets
            ## if fusion is enabled
            if key == 'continuousBackupEnabled':
                self.create_bucket('test', 1,
                                   params | {'fusionEnabled': 'false'})

            self.create_bucket('fusion', 1)

            resp = self.cluster.update_bucket({'name': 'fusion'} |
                                              params, expected_code=400)
            get_json_error(resp.json(), key)
            testlib.delete_all_buckets(self.cluster)

    def abort_rebalance_test(self):
        self.init_fusion()
        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        second_node = self.cluster.spare_node()
        self.create_bucket('test', 1)

        self.cluster.add_node(second_node, services=[Service.KV])

        otp_nodes = testlib.get_otp_nodes(self.cluster)

        testlib.post_fail(
            self.cluster,
            f"/controller/fusion/abortPreparedRebalance?planUUID=wrong",
            expected_code=404)

        acc_plan = self.prepare_rebalance(otp_nodes.values())
        plan_uuid = acc_plan["planUUID"]

        testlib.post_fail(
            self.cluster,
            f"/controller/fusion/abortPreparedRebalance?planUUID=wrong",
            expected_code=400)

        testlib.post_succ(
            self.cluster,
            f"/controller/fusion/abortPreparedRebalance?planUUID={plan_uuid}")

        testlib.post_fail(
            self.cluster,
            f"/controller/fusion/abortPreparedRebalance?planUUID={plan_uuid}",
            expected_code=404)

    def get_namespaces(self, node):
        resp = testlib.diag_eval(
            node,
            '{ok, Json} = ns_memcached:get_fusion_namespaces(' +
            '      fusion_uploaders:get_metadata_store_uri()),' +
            '{Parsed} = ejson:decode(Json),' +
            'Namespaces = proplists:get_value(<<"namespaces">>, Parsed),' +
            'Res =' +
            '  lists:map(' +
            '    fun (Namespace) ->' +
            '      [_, UUID] = string:tokens(binary_to_list(Namespace), "/"),' +
            '      BinUUID = list_to_binary(UUID),' +
            '      {ok, BucketName} = ns_bucket:uuid2bucket(BinUUID),' +
            '      list_to_binary(BucketName)' +
            '    end, Namespaces),' +
            '{json, lists:sort(Res)}.')
        return json.loads(resp.text)

    def assert_namespaces(self, expected):
        for node in self.cluster.connected_nodes:
            namespaces = self.get_namespaces(node)
            assert namespaces == expected

    def enable_disable_stop_test(self):
        self.init_fusion()

        self.create_bucket('test', 1)
        self.create_bucket('test1', 1)

        second_node = self.cluster.spare_node()
        self.cluster.add_node(second_node, services=[Service.KV])
        self.cluster.rebalance()
        self.assert_namespaces([])

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')
        self.assert_bucket_state('test', 'enabled')
        self.assert_bucket_state('test1', 'enabled')
        self.assert_namespaces(['test', 'test1'])

        testlib.post_succ(self.cluster, '/fusion/disable')
        self.wait_for_state('disabling', 'disabled')
        self.assert_bucket_state('test', 'disabled')
        self.assert_bucket_state('test1', 'disabled')
        self.assert_namespaces([])

        testlib.post_succ(self.cluster, '/fusion/enable',
                          data={'buckets': 'test'})
        self.wait_for_state('enabling', 'enabled')
        self.assert_bucket_state('test', 'enabled')
        self.assert_bucket_state('test1', 'disabled')
        self.assert_namespaces(['test'])

        testlib.post_succ(self.cluster, '/fusion/stop')
        self.wait_for_state('stopping', 'stopped')
        self.assert_bucket_state('test', 'stopped')
        self.assert_bucket_state('test1', 'disabled')
        self.assert_namespaces(['test'])

        testlib.post_succ(self.cluster, '/fusion/enable',
                          data={'buckets': 'test'})
        self.wait_for_state('enabling', 'enabled')
        self.assert_bucket_state('test', 'enabled')
        self.assert_bucket_state('test1', 'disabled')
        self.assert_namespaces(['test'])

        testlib.post_succ(self.cluster, '/fusion/stop')
        self.wait_for_state('stopping', 'stopped')
        self.assert_bucket_state('test', 'stopped')
        self.assert_bucket_state('test1', 'disabled')
        self.assert_namespaces(['test'])

        testlib.post_succ(self.cluster, '/fusion/disable')
        self.wait_for_state('disabling', 'disabled')
        self.assert_bucket_state('test', 'disabled')
        self.assert_bucket_state('test1', 'disabled')
        self.assert_namespaces([])

        metrics = testlib.get_prometheus_metrics(self.cluster)
        verify_gauge_metric(metrics, "cm_fusion_state_timestamp_seconds",
                            [(('state', 'disabled'),),
                             (('state', 'disabling'),),
                             (('state', 'enabled'),),
                             (('state', 'enabling'),),
                             (('state', 'stopped'),),
                             (('state', 'stopping'),)])

        verify_gauge_metric(metrics, "cm_fusion_bucket_state_timestamp_seconds",
                            [(('bucket', 'test'), ('state', 'disabling')),
                             (('bucket', 'test'), ('state', 'disabled')),
                             (('bucket', 'test'), ('state', 'enabled')),
                             (('bucket', 'test'), ('state', 'stopping'),),
                             (('bucket', 'test'), ('state', 'stopped'),),
                             (('bucket', 'test1'), ('state', 'enabled')),
                             (('bucket', 'test1'), ('state', 'disabling')),
                             (('bucket', 'test1'), ('state', 'disabled'))])

    def enable_from_disabling_test(self):
        self.init_fusion()

        self.create_bucket('test', 1)
        self.create_bucket('test1', 1)

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')
        self.assert_bucket_state('test', 'enabled')
        self.assert_bucket_state('test1', 'enabled')
        self.assert_namespaces(['test', 'test1'])

        testlib.testconditions_set(self.cluster, 'maybe_advance_state',
                                   '{return, disabling, skip}')

        testlib.post_succ(self.cluster, '/fusion/disable')
        self.assert_bucket_state('test', 'disabling')
        self.assert_bucket_state('test1', 'disabling')

        def got_400():
            resp = testlib.post(self.cluster, '/fusion/enable',
                                data={'buckets': 'test'})
            if resp.status_code == 400:
                return True
            assert resp.status_code == 503, \
                testlib.format_http_error(resp, [503, 400])
            return False

        testlib.poll_for_condition(
            got_400, 1, attempts=60,
            msg='Wait for /fusion/enable code to change from 503 to 400')

        self.assert_bucket_state('test', 'disabling')
        self.assert_bucket_state('test1', 'disabling')
        self.assert_namespaces([])

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')
        self.assert_bucket_state('test', 'enabled')
        self.assert_bucket_state('test1', 'enabled')
        self.assert_namespaces(['test', 'test1'])

    def get_snapshot_uuids(self):
        resp = testlib.diag_eval(
            self.cluster,
            'List = fusion_uploaders:get_stored_snapshot_uuids(),' +
            'JsonList = [{[{plan_uuid, PlanUUID},' +
            '              {bucket_uuid, BucketUUID},' +
            '              {num_vbuckets, NVBuckets}]} ||' +
            '                  {PlanUUID, BucketUUID, NVBuckets} <- List],' +
            '{json, JsonList}.')
        return json.loads(resp.text)

    def get_uploaders(self, bucket):
        resp = testlib.diag_eval(
            self.cluster,
            f'Res = ns_bucket:get_fusion_uploaders("{bucket}"),' +
            '{json, [{[{node, N}, {term, T}]} || {N, T} <- Res]}.')
        return json.loads(resp.text)

    def check_uploaders(self, bucket):
        vbucket_map = self.cluster.get_vbucket_map(bucket)
        uploaders = self.get_uploaders(bucket)
        testlib.assert_eq(len(uploaders), len(vbucket_map))

        for vbucket, chain in enumerate(vbucket_map):
            testlib.assert_not_eq(None, chain[0])
            testlib.assert_eq(uploaders[vbucket]['node'], chain[0])

    def snapshot_management_test(self):
        self.init_fusion()
        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        second_node = self.cluster.spare_node()
        self.create_bucket('test', 1)
        bucket_uuid = self.cluster.get_bucket_uuid('test')

        self.cluster.add_node(second_node, services=[Service.KV])

        otp_nodes = testlib.get_otp_nodes(self.cluster)

        acc_plan = self.prepare_rebalance(otp_nodes.values())
        plan_uuid = acc_plan["planUUID"]

        uuids = self.get_snapshot_uuids()

        assert len(uuids) == 1
        snapshot_uuid = uuids[0]
        assert snapshot_uuid["plan_uuid"] == plan_uuid
        assert snapshot_uuid["bucket_uuid"] == bucket_uuid
        assert snapshot_uuid["num_vbuckets"] == 16

    def swap_rebalance_test(self):
        self.init_fusion()

        self.create_bucket('test', 1)

        disconnected_nodes = self.cluster.disconnected_nodes()
        second_node = disconnected_nodes[0]
        third_node = disconnected_nodes[1]

        self.cluster.add_node(second_node, services=[Service.KV])
        self.cluster.rebalance()

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        self.cluster.add_node(third_node, services=[Service.KV])
        keep_nodes = [self.cluster.connected_nodes[0].otp_node(),
                      third_node.otp_node()]
        acc_plan = self.prepare_rebalance(keep_nodes)
        plan_uuid = acc_plan["planUUID"]

        testlib.post_succ(
            self.cluster,
            f"/controller/fusion/uploadMountedVolumes?planUUID={plan_uuid}",
            json=generate_nodes_volumes([third_node.otp_node()]))

        self.cluster.rebalance(ejected_nodes=[second_node],
                               plan_uuid = plan_uuid,
                               wait = True)
        self.check_uploaders('test')

    def prepare_2_nodes_one_bucket(self):
        self.init_fusion()
        self.create_bucket('test', 1)

        first_node = self.cluster.connected_nodes[0]

        disconnected_nodes = self.cluster.disconnected_nodes()
        second_node = disconnected_nodes[0]

        self.cluster.add_node(second_node, services=[Service.KV])
        self.cluster.rebalance()

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        return first_node, second_node

    def rebalance_out_the_last_replica_test(self):
        first_node, second_node = self.prepare_2_nodes_one_bucket()
        first_node_otp = first_node.otp_node()

        acc_plan = self.prepare_rebalance([first_node_otp])

        plan_nodes = acc_plan["nodes"]
        assert len(plan_nodes) == 0

        plan_uuid = acc_plan["planUUID"]

        testlib.post_succ(
            self.cluster,
            f"/controller/fusion/uploadMountedVolumes?planUUID={plan_uuid}",
            json={'nodes': []})

        self.cluster.rebalance(ejected_nodes=[second_node],
                               plan_uuid = plan_uuid,
                               wait = True)

        self.check_uploaders('test')

    def rebalance_with_trivial_moves_test(self):
        _, second_node = self.prepare_2_nodes_one_bucket()
        self.cluster.failover_node(second_node, graceful=True)
        self.cluster.eject_node(second_node, second_node)
        self.cluster.rebalance(wait = True)
        self.check_uploaders('test')

    def disable_fusion_via_config_remap_test(self):
        self.init_fusion()
        self.create_bucket('test', 1)

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        print(f"Shutting down original cluster at node index "
              f"{self.cluster.first_node_index}")

        self.cluster.stop_all_nodes()

        print(f"Shut down original cluster at node index "
              f"{self.cluster.first_node_index}")

        wrapper_args = [
            '--just-disable-auto-failover',
            '--rewrite', '[fusion_config, log_store_uri]', '"local://002"',
            '--rewrite', '[fusion_config, enable_sync_threshold_mb]', '1000',
            '--disable-fusion']

        ConfigRemapTest.run_config_remap(self, self.cluster, wrapper_args)

        print(f"Starting original cluster at node index "
              f"{self.cluster.first_node_index}")

        self.cluster.restart_all_nodes()

        self.wait_for_state('disabling', 'disabled')
        self.assert_bucket_state('test', 'disabled')

    def prep_restore(self, ndocs):
        self.init_fusion()

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        self.create_bucket('default', 1)

        # set small upload interval
        testlib.post_succ(self.cluster,
                          '/pools/default/buckets/default?internal=1',
                          data={'magmaFusionUploadInterval': 30})

        testlib.load_data(self.cluster, 'default', num_items=ndocs,
                          min_size=1024, max_size=1024)

        testlib.wait_for_data(self.cluster, 'default', ndocs)

        testlib.post_succ(self.cluster, "/controller/fusion/syncLogStore")

        # This is a hack so that files on LogStore don't change.
        # In real use case, this cluster will no longer be used.
        testlib.post_succ(
            self.cluster,
            "/pools/default/settings/memcached/global",
            data={'fusion_sync_rate_limit': 0},
            expected_code=202)

        work_dir = self.cluster.backup_dir
        manifest_path = os.path.join(work_dir, 'backup_manifest.json')

        bucket_uuid = self.cluster.get_bucket_uuid('default')
        namespace = f"kv/{bucket_uuid}"
        manifest = self.accelerator_get_manifest(manifest_path, namespace)
        assert manifest.get('volumes'), \
            f"accelerator returned empty volumes for namespace {namespace}; " \
            f"the LogStore was likely not synced (check fusion_sync_rate_limit)"
        expected_terms = [u['term'] + 1 for u in self.get_uploaders('default')]

        second_node = self.cluster.spare_node()
        self.cluster.add_node(second_node, services=[Service.KV])
        self.cluster.rebalance()

        # Build restore request from manifest
        restore_request = {
            'buckets': [{
                'config': {
                    'name': 'defaultClone',
                    'replicaNumber': 1,
                    'ramQuotaMB': 256
                },
                'manifest': manifest
            }]
        }

        # Prepare the snapshot restore plan.
        resp = testlib.post_succ(
            self.cluster,
            '/controller/fusion/prepareSnapshotRestore',
            json=restore_request)
        restore_plan = resp.json()
        assert isinstance(restore_plan, dict), \
            f"Expected dict response, got: {type(restore_plan)}"
        restore_plan_uuid = restore_plan["planUUID"]

        restore_plan_path = os.path.join(work_dir, 'restore_plan.json')
        with open(restore_plan_path, 'w') as f:
            json.dump(restore_plan, f)

        # Expand and split the plan across 2 accelerators
        acc_manifests_dir = os.path.join(
            work_dir, f'acc_manifests_{restore_plan_uuid}')
        self.accelerator_split_manifest(
            restore_plan_path, 2, acc_manifests_dir)

        # Download files for snapshot restore plan
        guest_volumes_dir = os.path.join(
            work_dir, f'guest_volumes_{restore_plan_uuid}')
        for i in range(1, 3):
            part_manifest = glob.glob(
                os.path.join(acc_manifests_dir, '*', f'part{i}.json'))[0]
            guest_vol_dest = os.path.join(guest_volumes_dir, str(i))
            os.makedirs(guest_vol_dest, exist_ok=True)

            # Download from source LogStore to guest volume
            self.accelerator_download_files(
                part_manifest, guest_vol_dest, self.cluster.logstore_dir)

            # Download from source LogStore to destination LogStore
            self.accelerator_download_files(
                part_manifest, self.cluster.logstore_dir,
                self.cluster.logstore_dir)

        # Restore snapshot (synchronous API)
        guest_volume_paths = [
            os.path.join(guest_volumes_dir, '1'),
            os.path.join(guest_volumes_dir, '2')
        ]
        restore_body = {
            'nodes': [{
                'name': self.cluster.connected_nodes[0].otp_node(),
                'guestVolumePaths': guest_volume_paths
            },
            {
                'name': self.cluster.connected_nodes[1].otp_node(),
                'guestVolumePaths': guest_volume_paths
            }]
        }
        return (restore_body, restore_plan_uuid, expected_terms)

    def restore_test(self):
        ndocs = 1000

        (restore_body, restore_plan_uuid,
         expected_terms) = self.prep_restore(ndocs)

        testlib.post_succ(
            self.cluster,
            f'/controller/fusion/restoreSnapshot?planUUID={restore_plan_uuid}',
            json=restore_body)

        # check that all documents present in the new bucket using direct
        # call to ns_memcached. testlib.wait_for_data is not useful here,
        # because we need to ensure that all the docs appear right after
        # restoreSnapshot API returns
        total = self.get_curr_items_tot(self.cluster.connected_nodes,
                                        'defaultClone')
        testlib.assert_eq(total, ndocs * 2)

        restored_terms = [u['term'] for u in self.get_uploaders('defaultClone')]
        assert restored_terms == expected_terms, (
            f"Expected uploader terms {expected_terms}, "
            f"got {restored_terms}"
        )

        # check that the data on LogStore is fully restored
        status = self.get_status()
        nodes = status.get('nodes', {})
        for node in nodes.values():
            buckets = node.get('buckets', {})
            for bucket in buckets.values():
                pending = bucket.get('snapshotPendingBytes', 0)
                assert pending == 0

        # check that cluster is balanced -- no rebalance pending after
        # restore.
        pool = testlib.get_succ(self.cluster, '/pools/default').json()
        assert pool.get('balanced') == True, (
            f"Expected cluster to be balanced after restore, got: "
            f"balanced={pool.get('balanced')}, "
            f"servicesNeedRebalance={pool.get('servicesNeedRebalance')}, "
            f"bucketsNeedRebalance={pool.get('bucketsNeedRebalance')}"
        )

    def restore_failure_test(self):
        (restore_body, restore_plan_uuid,
         expected_terms) = self.prep_restore(100)

        testlib.testconditions_set(self.cluster, 'restore_fusion_bucket',
                                   '{return, "defaultClone", fail}')

        testlib.post_fail(
            self.cluster,
            f'/controller/fusion/restoreSnapshot?planUUID={restore_plan_uuid}',
            json=restore_body, expected_code=500)

        def create_bucket():
            try:
                self.create_bucket('defaultClone', 1)
                return True
            except AssertionError:
                return False

        testlib.poll_for_condition(
            create_bucket, 1, attempts=60,
            msg=f"Wait for bucket name to become available")

    def get_curr_items_tot(self, nodes, bucket):
        total = 0
        for node in nodes:
            resp = testlib.diag_eval(
                node,
                f'{{ok, Stats}} = ns_memcached:stats("{bucket}", <<"">>),'
                f'Value = proplists:get_value(<<"curr_items_tot">>, Stats),'
                f'binary_to_integer(Value).')
            total += int(resp.text.strip())
        return total

    def run_accelerator_cli(self, subcommand, *args):
        accelerator_cli = os.path.join(
            testlib.get_bin_dir(), 'fusion', 'accelerator-cli')
        cmd = [accelerator_cli, subcommand, *args]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, \
            f"accelerator-cli {subcommand} failed: " \
            f"stdout={result.stdout} stderr={result.stderr}"
        return result

    def accelerator_download_files(self, manifest_path, dest, base_uri):
        self.run_accelerator_cli(
            'download-files',
            '-manifest', manifest_path,
            '-dest', dest,
            '-base-uri', base_uri)

    def accelerator_split_manifest(self, manifest_path, parts, output_dir):
        self.run_accelerator_cli(
            'split-manifest',
            '-manifest', manifest_path,
            '-parts', str(parts),
            '-base-uri', self.cluster.logstore_dir,
            '-output-dir', output_dir,
            '-min-storage-size', '0')

    def accelerator_get_manifest(self, manifest_path, namespace):
        self.run_accelerator_cli(
            'generate-manifest',
            '-base-uri', self.cluster.logstore_dir,
            '-namespace', namespace,
            '-type', 'namespace',
            '-manifest', manifest_path)

        with open(manifest_path, 'r') as f:
            manifest = json.load(f)

        return manifest


def assert_buckets_error(json, expected):
    error_message = get_json_error(json, 'buckets')

    prefix = "Fusion cannot be enabled on the following buckets: "
    assert error_message.startswith(prefix), (
        f"Error message should start with '{prefix}', got: {error_message}"
    )
    content = error_message[len(prefix):].strip()
    # match substrings in a comma-separated list where individual
    # items follow a "key - value" format,
    pattern = r'([^,]+?)\s*-\s*(.+?)(?:,\s*|$)'
    matches = re.findall(pattern, content)

    actual = {}
    for bucket, reason in matches:
        bucket = bucket.strip()
        reason = reason.strip()
        actual[bucket] = reason

    assert actual == expected, (
        f"Parsed errors don't match.\nExpected: {expected}\nGot: {actual}"
    )

def get_json_error(json, field):
    assert isinstance(json, dict)
    assert "errors" in json

    errors = json["errors"]
    assert isinstance(errors, dict)
    assert field in errors

    value = errors[field]
    assert isinstance(value, str)
    return value

def assert_json_error(json, field, prefix):
    value = get_json_error(json, field)
    assert value.startswith(prefix)


# Errors reported by validator:json_array come back as a list with one object
# per element of the array (empty for elements without errors). This extracts
# the error for a given field of the bucket at the given index.
def assert_bucket_error(json, index, field, expected):
    assert isinstance(json, dict)
    assert "errors" in json, f"'errors' not in response: {json}"
    errors = json["errors"]
    assert isinstance(errors, dict)
    assert "buckets" in errors, f"'buckets' not in errors: {errors}"
    buckets = errors["buckets"]
    assert isinstance(buckets, list), \
        f"expected list of per-bucket errors, got: {buckets}"
    assert index < len(buckets), \
        f"no bucket error at index {index}: {buckets}"
    elem = buckets[index]
    assert isinstance(elem, dict)
    assert field in elem, f"'{field}' not in bucket error: {elem}"
    assert elem[field] == expected, \
        f"expected '{expected}', got '{elem[field]}'"


def generate_nodes_volumes(nodes):
    gv_paths = ["/tmp/data1", "/tmp/data2", "/tmp/data3"]
    nodes_volumes = [{'name': n,
                      'guestVolumePaths': random.sample(gv_paths,
                                                        random.randint(1, 2))}
                     for n in nodes]
    return {'nodes': nodes_volumes}

def verify_gauge_metric(metrics, metric, labels):
    assert metric in metrics
    mdict = metrics[metric]
    assert mdict["TYPE"] == "gauge"
    assert mdict["HELP"] != "Help is missing"
    vdict = mdict["VALUES"]

    for label_tuple in labels:
        assert label_tuple in vdict
