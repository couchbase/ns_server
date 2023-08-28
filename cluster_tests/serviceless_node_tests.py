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
        # Wait for the number of remaining nodes in the cluster to reach one.
        retries = 60
        while retries > 0:
            resp = testlib.get_succ(cluster, "/pools/default")
            current_nodes = [node["hostname"] for node in resp.json()["nodes"]]
            print(f"Nodes currently in cluster: {current_nodes}")
            if len(resp.json()["nodes"]) == 1:
                cluster.wait_nodes_up()
                return

            print(f'More than one node in cluster after removing all but one '
                  f'node. Retrying up to {retries} more times')
            time.sleep(0.5)
            retries -= 1

        raise RuntimeError("More than one node in cluster after test teardown")

    @staticmethod
    def requirements():
        return [ClusterRequirements(num_nodes=3, num_connected=1,
                                    afamily="ipv4")]

    def joinNodes(self, cluster):
        for node in cluster.nodes[1:]:
            print(f'Joining {node.hostname()} to cluster')
            cluster.do_join_cluster(node, services="")
        cluster.rebalance(wait=True)
        resp = testlib.get_succ(cluster, "/pools/default")

        return len(resp.json()["nodes"]) == self.req_num_nodes, \
            f'Length of nodes: {len(resp.json()["nodes"])}'

    def addNodes(self, cluster):
        for node in cluster.nodes[1:]:
            print(f'Adding {node.hostname()} to cluster')
            cluster.add_node(node, services="")
        cluster.rebalance(wait=True)
        resp = testlib.get_succ(cluster, "/pools/default")

        return len(resp.json()["nodes"]) == self.req_num_nodes, \
            f'Length of nodes: {len(resp.json()["nodes"])}'

    def failover_and_recover_node(self, cluster):
        node = cluster.nodes[-1]
        print(f'Failover {node.hostname()} from cluster')
        # Graceful failovers are not supported for serviceless nodes. We
        # don't do a rebalance as that would remove the node.
        resp = cluster.failover_node(node, graceful=False, verbose=True)

        print(f'Re-adding {node.hostname()} back into cluster')

        resp = cluster.recover_node(node, recovery_type="full",
                                    do_rebalance=True, verbose=True)

    def remove_orchestrator_node(self, cluster):
        orchestrator_node = cluster.wait_for_orchestrator()
        cluster.rebalance(ejected_nodes=[orchestrator_node], wait=True,
                          verbose=True)

    def verify_orchestrator_node(self, cluster, must_be_serviceless_node=True):
        retries = 60
        while retries > 0:
            orchestrator_hostname, is_serviceless = \
                cluster.get_orchestrator_node()
            if orchestrator_hostname != "" and \
               is_serviceless == must_be_serviceless_node:
                return
            time.sleep(0.5)
            retries -= 1

        if orchestrator_hostname == "":
            raise RuntimeError("Failed to determine orchestator")
        else:
            reason = "not" if must_be_serviceless_node else ""
            raise RuntimeError(f"Orchestrator node {orchestrator_hostname} is "
                               f"unexpectedly {reason} serviceless")

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
