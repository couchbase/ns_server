# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
from testlib import ClusterRequirements
import time

# Testing of serviceless nodes (nodes that don't have any services, e.g.
# kv, index, etc. configured).


class ServicelessNodeTests(testlib.BaseTestSet):

    def __init__(self, cluster):
        super().__init__(cluster)
        self.req_num_nodes = None

    def setup(self, cluster):
        self.req_num_nodes = len(cluster.nodes)
        testlib.delete_all_buckets(cluster)
        bucket = {"name": "testbucket", "ramQuota": "200"}
        self.cluster.create_bucket(bucket)

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        print("Tearing down cluster")
        testlib.delete_all_buckets(cluster)
        # Rebalance the cluster and remove all but one node
        cluster.rebalance(cluster.nodes[1:], wait=True, verbose=True)
        # Allow time for changes to take affect otherwise the below
        # /pools/default sometimes returns the ejected node.
        time.sleep(2)
        resp = testlib.get_succ(cluster, "/pools/default")
        print([node["hostname"] for node in resp.json()["nodes"]])
        if len(resp.json()["nodes"]) != 1:
            print(f'Length of nodes: {len(resp.json()["nodes"])}')
            print([node["hostname"] for node in resp.json()["nodes"]])
            raise ValueError("More than one node in cluster after test "
                             "teardown")
        cluster.wait_nodes_up()

    @staticmethod
    def requirements():
        return [ClusterRequirements(num_nodes=3, num_connected=1,
                                    afamily="ipv4")]

    def joinNodes(self, cluster):
        for node in cluster.nodes[1:]:
            print(f'Joining {node.hostname} to cluster')
            cluster.do_join_cluster(node, services="")
        cluster.rebalance(wait=True)
        resp = testlib.get_succ(cluster, "/pools/default")

        return len(resp.json()["nodes"]) == self.req_num_nodes, \
            f'Length of nodes: {len(resp.json()["nodes"])}'

    def addNodes(self, cluster):
        for node in cluster.nodes[1:]:
            print(f'Adding {node.hostname} to cluster')
            cluster.add_node(node, services="")
        cluster.rebalance(wait=True)
        resp = testlib.get_succ(cluster, "/pools/default")

        return len(resp.json()["nodes"]) == self.req_num_nodes, \
            f'Length of nodes: {len(resp.json()["nodes"])}'

    def failover_and_recover_node(self, cluster):
        node = cluster.nodes[-1]
        print(f'Failover {node.hostname} from cluster')
        # Graceful failovers are not supported for serviceless nodes
        resp = cluster.failover_node(node, graceful=False, do_rebalance=True,
                                     verbose=True)

        print(f'Re-adding {node.hostname} back into cluster')

        resp = cluster.recover_node(node, recovery_type="full",
                                    do_rebalance=True, verbose=True)

    def remove_orchestrator_node(self, cluster):
        orchestrator_hostname = self.get_orchestrator_node(cluster)
        for node in cluster.nodes:
            if node.hostname == orchestrator_hostname:
                cluster.rebalance(ejected_nodes=[node], wait=True, verbose=True)
                return
        raise RuntimeError("orchestrator node not found")

    def get_orchestrator_node(self, cluster, must_be_serviceless_node=None):
        # Allow time for orchestrator determination to complete
        time.sleep(5)
        resp = testlib.get_succ(cluster, "/pools/default/terseClusterInfo")
        orchestrator = resp.json()['orchestrator']
        resp = testlib.get_succ(cluster, "/pools/nodes").json()
        nodes = resp['nodes']
        orchestrator_hostname = ""
        for i in range(len(resp["nodes"])):
            if nodes[i]['otpNode'] == orchestrator:
                assert orchestrator_hostname == ""
                orchestrator_hostname = nodes[i]['hostname']
                if must_be_serviceless_node is not None:
                    if must_be_serviceless_node:
                        assert nodes[i]['services'] == []
                    else:
                        assert nodes[i]['services'] != []
        assert orchestrator_hostname != "", "No orchestrator node found"
        return orchestrator_hostname

    def verify_orchestrator_node(self, cluster, must_be_serviceless_node=True):
        self.get_orchestrator_node(cluster, must_be_serviceless_node)

    # These tests are based on a cluster which has the initial node with
    # services and two additional serviceless nodes.
    def addnode_test(self, cluster):
        self.verify_orchestrator_node(cluster, False)
        self.addNodes(cluster)
        self.verify_orchestrator_node(cluster, True)
        self.failover_and_recover_node(cluster)
        self.verify_orchestrator_node(cluster, True)
        # Removing the orchestrator node should result in the remaining
        # serviceless node becoming the orchestrator
        self.remove_orchestrator_node(cluster)
        self.verify_orchestrator_node(cluster, True)

    def joincluster_test(self, cluster):
        self.verify_orchestrator_node(cluster, False)
        self.joinNodes(cluster)
        self.verify_orchestrator_node(cluster, True)
        self.failover_and_recover_node(cluster)
        self.verify_orchestrator_node(cluster, True)
        # Removing the orchestrator node should result in the remaining
        # serviceless node becoming the orchestrator
        self.remove_orchestrator_node(cluster)
        self.verify_orchestrator_node(cluster, True)
