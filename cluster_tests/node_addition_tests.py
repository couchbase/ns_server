# @author Couchbase <info@couchbase.com>
# @copyright 2023 Couchbase, Inc.
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
from testlib import ClusterRequirements


class NodeAdditionTests(testlib.BaseTestSet):

    def __init__(self, cluster):
        super().__init__(cluster)
        self.disconnected_nodes = None
        self.req_num_nodes = None

    def setup(self, cluster):
        self.req_num_nodes = len(cluster.nodes)
        self.disconnected_nodes = [node for node in cluster.nodes
                                   if node not in cluster.connected_nodes]
        testlib.delete_all_buckets(cluster)

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        print("Removing all but the first node")
        # Rebalance the cluster and remove all but one node
        cluster.rebalance(cluster.connected_nodes[1:], wait=True, verbose=True)

        # Verify that the cluster has the correct number of nodes.
        # Note that if this fails then we will cause future testsets to fail.
        assert_cluster_size(cluster, 1)
        cluster.wait_nodes_up()

    @staticmethod
    def requirements():
        return [ClusterRequirements(num_nodes=3, num_connected=1,
                                    afamily="ipv4"),
                ClusterRequirements(num_nodes=3, num_connected=1,
                                    afamily="ipv6")]

    def n2n_test_base(self, cluster, method, enable: bool):
        """
        A base structure of testing node to node encryption with adding nodes.
        :param cluster: Cluster object to send requests to
        :param method: which REST request to add nodes:
                       cluster.add_node/cluster.do_join_cluster
        :param enable: whether node-to-node encryption is enabled or disabled
        """
        # Change the node-to-node settings.
        toggle_n2n(cluster, enable=enable)

        # Test a node addition method
        for node in self.disconnected_nodes:
            method(node)
        cluster.rebalance(wait=True)

        # Verify that the cluster has the correct number of nodes
        assert_cluster_size(cluster, self.req_num_nodes)

        # Verify all nodes, including the new node, have the correct n2n setting
        assert_n2n(cluster, enable)

    def n2n_off_addnode_test(self, cluster):
        self.n2n_test_base(cluster, cluster.add_node, False)

    def n2n_on_addnode_test(self, cluster):
        self.n2n_test_base(cluster, cluster.add_node, True)

    def n2n_off_joincluster_test(self, cluster):
        self.n2n_test_base(cluster, cluster.do_join_cluster, False)

    def n2n_on_joincluster_test(self, cluster):
        self.n2n_test_base(cluster, cluster.do_join_cluster, True)


# Assert that all nodes have node-to-node encryption enabled/disabled
def assert_n2n(cluster, expected_value):
    r = testlib.get_succ(cluster, "/pools/default")
    bad_nodes = [node['hostname'] for node in r.json()['nodes']
                 if node['nodeEncryption'] != expected_value]
    assert len(bad_nodes) == 0, \
        f"Expected nodeEncryption to be {expected_value} for all nodes, " \
        f"but got {not expected_value} for the following nodes: {bad_nodes}"


# Assert that the cluster has the expected size
def assert_cluster_size(cluster, expected_size):
    resp = testlib.get_succ(cluster, "/pools/default")
    nodes = [node["hostname"] for node in resp.json()["nodes"]]
    assert len(nodes) == expected_size, \
        f"Wrong number of nodes in cluster. Expected {expected_size} " \
        f"nodes, found the following set of nodes: {nodes}"


def toggle_n2n(cluster, enable=True):
    """
    Helper function to enable/disable node to node encryption for all nodes
    :param cluster: Cluster object to send requests to
    :param enable: Whether node to node encryption should be enabled.
    """
    # Need to disable autoFailover before other settings can change
    testlib.post_succ(cluster, "/settings/autoFailover",
                      data={"enabled": "false"})

    for node in cluster.connected_nodes:
        # Create an external listener
        testlib.post_succ(node, "/node/controller/enableExternalListener",
                          data={"nodeEncryption": "on"
                                if enable else "off"})

        # Change the node-to-node encryption settings
        testlib.post_succ(node, "/node/controller/setupNetConfig",
                          data={"nodeEncryption": "on"
                                if enable else "off"})
        # Disable any unused listeners
        testlib.post_succ(node,
                          "/node/controller/disableUnusedExternalListeners")

    # Re-enable autoFailover.
    testlib.post_succ(cluster, "/settings/autoFailover",
                      data={"enabled": "true",
                            "timeout": 120})

    assert_n2n(cluster, enable)
