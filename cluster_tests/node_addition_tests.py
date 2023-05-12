import testlib
from testlib import ClusterRequirements


class NodeAdditionTests(testlib.BaseTestSet):

    def __init__(self, cluster):
        super().__init__(cluster)
        self.req_num_nodes = None

    def setup(self, cluster):
        self.req_num_nodes = len(cluster.nodes)
        testlib.delete_all_buckets(cluster)

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        print("Tearing down cluster")
        # Rebalance the cluster and remove all but one node
        cluster.rebalance(cluster.nodes[1:], wait=True, verbose=True)
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
                                    afamily="ipv4"),
                ClusterRequirements(num_nodes=3, num_connected=1,
                                    afamily="ipv6")]

    def joinCluster(self, cluster):
        for node in cluster.nodes[1:]:
            cluster.do_join_cluster(node)
        cluster.rebalance(wait=True)
        resp = testlib.get_succ(cluster, "/pools/default")

        return len(resp.json()["nodes"]) == self.req_num_nodes, \
            f'Length of nodes: {len(resp.json()["nodes"])}'

    def addNode(self, cluster):
        for node in cluster.nodes[1:]:
            cluster.add_node(node)
        cluster.rebalance(wait=True)
        resp = testlib.get_succ(cluster, "/pools/default")

        return len(resp.json()["nodes"]) == self.req_num_nodes, \
            f'Length of nodes: {len(resp.json()["nodes"])}'

    def check_all_n2n(self, cluster, enable):
        # Check that all the nodes have node-to-node encryption.
        r = testlib.get_succ(cluster, "/pools/nodes")
        return all([node["nodeEncryption"] == enable
                    for node in r.json()["nodes"]])

    def toggle_n2n(self, cluster, enable=True):
        """
        Helper function to enable/disable node to node encryption
        :param cluster: From the cluster tuple in testlib.py
        :param enable: Whether node to node encryption should be enabled.
        """

        # Need to disable autoFailover before other settings can change
        testlib.post_succ(cluster, "/settings/autoFailover",
                          data={"enabled": "false"})

        # Create an external listener
        testlib.post_succ(cluster,
                          "/node/controller/enableExternalListener",
                          data={"nodeEncryption": "on" if enable else "off"})

        # Change the node-to-node encryption settings
        testlib.post_succ(cluster, "/node/controller/setupNetConfig",
                          data={"nodeEncryption": "on" if enable else "off"})
        # Disable any unused listeners
        testlib.post_succ(cluster,
                          "/node/controller/disableUnusedExternalListeners")

        # Re-enable autoFailover.
        testlib.post_succ(cluster, "/settings/autoFailover",
                          data={"enabled": "true",
                                "timeout": 120})

        return self.check_all_n2n(cluster, enable)

    def n2n_test_base(self, cluster, method, enable: bool):
        """
        A base structure of testing node to node encryption with adding nodes.
        :param cluster: Cluster class.
        :param method: which REST request to add nodes:
                       self.addNode/self.joinCluster
        :param enable: whether node-to-node encryption is enabled or disabled
        """
        # Change the node-to-node settings.
        change_n2n = self.toggle_n2n(cluster, enable=enable)
        if not change_n2n:
            assert False, f"Changing node-to-node encryption failed"
        test_result, test_message = method(cluster)

        check_n2n = self.check_all_n2n(cluster, enable)

        if not check_n2n:
            assert False, \
                f"Expected node-to-node encryption to be {enable}, " \
                f"but received " \
                f"{[node['nodeEncryption'] for node in r.json()['nodes']]}"
        assert test_result, test_message

    def n2n_off_addnode_test(self, cluster):
        self.n2n_test_base(cluster, self.addNode, False)

    def n2n_on_addnode_test(self, cluster):
        self.n2n_test_base(cluster, self.addNode, True)

    def n2n_off_joincluster_test(self, cluster):
        self.n2n_test_base(cluster, self.joinCluster, False)

    def n2n_on_joincluster_test(self, cluster):
        self.n2n_test_base(cluster, self.joinCluster, True)



