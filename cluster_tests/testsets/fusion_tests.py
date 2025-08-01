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
import json
import os
import shutil
import random

from testlib import ClusterRequirements
from testlib.util import Service

class FusionTests(testlib.BaseTestSet):

    def setup(self):
        node = self.cluster.connected_nodes[0]
        tmp_dir = node.tmp_path() + '/logstore'

        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)

        self.cluster.logstore_dir = tmp_dir

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

    @staticmethod
    def requirements():
        return [ClusterRequirements(edition="Enterprise",
                                    include_services=[Service.KV],
                                    min_num_nodes=2, num_connected=1,
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

    def create_bucket(self, name, num_replicas):
        self.cluster.create_bucket(
            {'name': name, 'ramQuota': 100, 'bucketType': 'membase',
             'storageBackend': 'magma', 'flushEnabled' : 1,
             'replicaNumber': num_replicas},
            sync=True)

    def prepare_rebalance(self, keep_nodes):
        keep_nodes_string = ",".join(keep_nodes.values())

        resp = testlib.post_succ(self.cluster,
                                 "/controller/fusion/prepareRebalance",
                                 data={'keepNodes': keep_nodes_string})
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
        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        second_node = self.cluster.spare_node()
        self.create_bucket('test', num_replicas)

        self.cluster.add_node(second_node, services=[Service.KV])

        otp_nodes = testlib.get_otp_nodes(self.cluster)
        second_otp_node = otp_nodes[second_node.hostname()]

        testlib.post_fail(self.cluster, "/controller/fusion/prepareRebalance",
                          expected_code=400)

        acc_plan = self.prepare_rebalance(otp_nodes)
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

        acc_plan = self.prepare_rebalance(otp_nodes)
        plan_uuid = acc_plan["planUUID"]

        nodes_volumes_json = {'nodes': [{'name': second_otp_node,
                                         'guestVolumePaths': []}]}

        # success
        resp = testlib.post_succ(
            self.cluster,
            f"/controller/fusion/uploadMountedVolumes?planUUID={plan_uuid}",
            json=nodes_volumes_json)

        self.cluster.rebalance(plan_uuid = plan_uuid)

        resp = testlib.get_succ(self.cluster, "/fusion/activeGuestVolumes")
        volumes = resp.json()
        assert volumes[second_otp_node] == []

    def bucket_flush_smoke_test(self):
        self.init_fusion()
        self.create_bucket('test', 1)
        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        resp = testlib.post_succ(
            self.cluster,
            f"/pools/default/buckets/test/controller/doFlush")

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
                          'enableSyncThresholdMB': 1024 * 100}
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
        nspaces0 = self.get_namespaces(self.cluster.connected_nodes[0])
        nspaces1 = self.get_namespaces(self.cluster.connected_nodes[1])
        assert nspaces0 == expected
        assert nspaces1 == expected

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

        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')
        self.assert_bucket_state('test', 'enabled')
        self.assert_bucket_state('test1', 'enabled')
        self.assert_namespaces(['test', 'test1'])

        testlib.post_succ(self.cluster, '/fusion/stop')
        self.wait_for_state('stopping', 'stopped')
        self.assert_bucket_state('test', 'stopped')
        self.assert_bucket_state('test1', 'stopped')
        self.assert_namespaces(['test', 'test1'])

        testlib.post_succ(self.cluster, '/fusion/disable')
        self.wait_for_state('disabling', 'disabled')
        self.assert_bucket_state('test', 'disabled')
        self.assert_bucket_state('test1', 'disabled')
        self.assert_namespaces([])

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

    def snapshot_management_test(self):
        self.init_fusion()
        testlib.post_succ(self.cluster, '/fusion/enable')
        self.wait_for_state('enabling', 'enabled')

        second_node = self.cluster.spare_node()
        self.create_bucket('test', 1)
        bucket_uuid = self.cluster.get_bucket_uuid('test')

        self.cluster.add_node(second_node, services=[Service.KV])

        otp_nodes = testlib.get_otp_nodes(self.cluster)

        acc_plan = self.prepare_rebalance(otp_nodes)
        plan_uuid = acc_plan["planUUID"]
        plan_nodes = acc_plan["nodes"]

        uuids = self.get_snapshot_uuids()

        assert len(uuids) == 1
        snapshot_uuid = uuids[0]
        assert snapshot_uuid["plan_uuid"] == plan_uuid
        assert snapshot_uuid["bucket_uuid"] == bucket_uuid
        assert snapshot_uuid["num_vbuckets"] == 16

def assert_json_error(json, field, prefix):
    assert isinstance(json, dict)
    assert len(json) == 1
    assert "errors" in json

    errors = json["errors"]
    assert isinstance(errors, dict)
    assert len(errors) == 1
    assert field in errors

    value = errors[field]
    assert isinstance(value, str)
    assert value.startswith(prefix)


def generate_nodes_volumes(nodes):
    gv_paths = ["/tmp/data1", "/tmp/data2", "/tmp/data3"]
    nodes_volumes = [{'name': n,
                      'guestVolumePaths': random.sample(gv_paths,
                                                        random.randint(1, 2))}
                     for n in nodes]
    return {'nodes': nodes_volumes}
