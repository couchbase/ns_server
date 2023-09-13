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
import os
from testlib import ClusterRequirements
from cert_load_tests import certs_path, generate_node_certs, load_ca, \
                            load_node_cert


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
        cluster.toggle_n2n_encryption(enable=enable)

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


class NodeAdditionWithCertsTests(testlib.BaseTestSet):
    @staticmethod
    def requirements():
        return ClusterRequirements(num_nodes=2, num_connected=1)

    def setup(self, cluster):
        def read_cert_file(filename):
            with open(os.path.join(certs_path, filename), 'r') as f:
                pem = f.read()
            return pem

        self.cluster_ca = read_cert_file('test_CA.pem')
        self.new_node_ca = read_cert_file('test_CA2.pem')
        self.cluster_ca_key = read_cert_file('test_CA.pkey')
        self.new_node_ca_key = read_cert_file('test_CA2.pkey')
        self.cluster_node_cert, self.cluster_node_key = \
            generate_node_certs(self.cluster_node(cluster).addr(),
                                self.cluster_ca, self.cluster_ca_key)
        self.new_node_cert, self.new_node_key = \
            generate_node_certs(self.new_node(cluster).addr(),
                                self.new_node_ca, self.new_node_ca_key)
        testlib.delete_all_buckets(cluster)

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        cluster.rebalance(cluster.connected_nodes[1:], wait=True, verbose=True)
        assert_cluster_size(cluster, 1)
        cluster.wait_nodes_up()
        for n in cluster.nodes:
            testlib.post_succ(n, '/controller/regenerateCertificate',
                              params={'forceResetCACertificate': 'false',
                                      'dropUploadedCertificates': 'true'})
            CAs = testlib.get_succ(n, '/pools/default/trustedCAs').json()
            for ca in CAs:
                testlib.delete(n, f'/pools/default/trustedCAs/{ca["id"]}')

    # Node addition is initiated by the-cluster-node:

    # Both nodes use custom certs:

    def add_trusted_node_to_trusted_cluster_test(self, cluster):
        self.provision_cluster_node(cluster)
        self.provision_new_node(cluster)
        load_ca(self.cluster_node(cluster), self.new_node_ca)
        load_ca(self.new_node(cluster), self.cluster_ca)
        cluster.add_node(self.new_node(cluster)).json()

    def add_trusted_node_to_untrusted_cluster_test(self, cluster):
        self.provision_cluster_node(cluster)
        self.provision_new_node(cluster)
        load_ca(self.cluster_node(cluster), self.new_node_ca)
        cluster.add_node(self.new_node(cluster))

    def add_untrusted_node_to_trusted_cluster_test(self, cluster):
        self.provision_cluster_node(cluster)
        self.provision_new_node(cluster)
        load_ca(self.new_node(cluster), self.cluster_ca)
        r = cluster.add_node(self.new_node(cluster), expected_code=400).json()
        assert_cluster_unknown_ca_error(r)

    def add_untrusted_node_to_untrusted_cluster_test(self, cluster):
        self.provision_cluster_node(cluster)
        self.provision_new_node(cluster)
        r = cluster.add_node(self.new_node(cluster), expected_code=400).json()
        assert_cluster_unknown_ca_error(r)

    # Cluster node uses ootb certs, new node uses custom certs:

    def add_trusted_node_to_trusted_ootb_cluster_test(self, cluster):
        load_ca(self.new_node(cluster), self.cluster_ootb_ca(cluster))
        load_ca(self.cluster_node(cluster), self.new_node_ca)
        self.provision_new_node(cluster)
        cluster.add_node(self.new_node(cluster))

    def add_trusted_node_to_untrusted_ootb_cluster_test(self, cluster):
        load_ca(self.cluster_node(cluster), self.new_node_ca)
        self.provision_new_node(cluster)
        cluster.add_node(self.new_node(cluster))

    def add_untrusted_node_to_trusted_ootb_cluster_test(self, cluster):
        load_ca(self.new_node(cluster), self.cluster_ootb_ca(cluster))
        self.provision_new_node(cluster)
        # Despite the fact that the-cluster-node is ootb, it always validates
        # new-node's certificates when doing completeJoin
        r = cluster.add_node(self.new_node(cluster), expected_code=400).json()
        assert_cluster_unknown_ca_error(r)

    def add_untrusted_node_to_untrusted_ootb_cluster_test(self, cluster):
        self.provision_new_node(cluster)
        r = cluster.add_node(self.new_node(cluster), expected_code=400).json()
        assert_cluster_unknown_ca_error(r)

    # Cluster node uses custom certs, new node uses ootb certs:

    def add_trusted_ootb_node_to_trusted_cluster_test(self, cluster):
        [ca_id] = load_ca(self.cluster_node(cluster),
                          self.new_node_ootb_ca(cluster))
        load_ca(self.new_node(cluster), self.cluster_ca)
        self.provision_cluster_node(cluster)
        cluster.add_node(self.new_node(cluster))
        # We can remove the ca that we added before, because the-new-node
        # should already use new certs now (new certs are regenerated during
        # node addition in this case)
        testlib.delete(cluster, f'/pools/default/trustedCAs/{ca_id}')

    def add_trusted_ootb_node_to_untrusted_cluster_test(self, cluster):
        [ca_id] = load_ca(self.cluster_node(cluster),
                          self.new_node_ootb_ca(cluster))
        self.provision_cluster_node(cluster)
        cluster.add_node(self.new_node(cluster))
        # We can remove the ca that we added before, because the-new-node
        # should already use new certs now (new certs are regenerated during
        # node addition in this case)
        testlib.delete(cluster, f'/pools/default/trustedCAs/{ca_id}')

    def add_untrusted_ootb_node_to_trusted_cluster_test(self, cluster):
        load_ca(self.new_node(cluster), self.cluster_ca)
        self.provision_cluster_node(cluster)
        r = cluster.add_node(self.new_node(cluster), expected_code=400).json()
        assert_cluster_unknown_ca_error(r)

    def add_untrusted_ootb_node_to_untrusted_cluster_test(self, cluster):
        self.provision_cluster_node(cluster)
        r = cluster.add_node(self.new_node(cluster), expected_code=400).json()
        assert_cluster_unknown_ca_error(r)

    # Node addition is iniated by the-new-node (node joins the cluster):

    # Both nodes use custom certs:

    def trusted_node_joins_trusted_cluster_test(self, cluster):
        load_ca(self.cluster_node(cluster), self.new_node_ca)
        load_ca(self.new_node(cluster), self.cluster_ca)
        self.provision_cluster_node(cluster)
        self.provision_new_node(cluster)
        cluster.do_join_cluster(self.new_node(cluster))

    def untrusted_node_joins_trusted_cluster_test(self, cluster):
        load_ca(self.new_node(cluster), self.cluster_ca)
        self.provision_cluster_node(cluster)
        self.provision_new_node(cluster)
        r = cluster.do_join_cluster(self.new_node(cluster),
                                    expected_code=400).json()
        assert_cluster_unknown_ca_error(r)

    def trusted_node_joins_untrusted_cluster_test(self, cluster):
        load_ca(self.cluster_node(cluster), self.new_node_ca)
        self.provision_cluster_node(cluster)
        self.provision_new_node(cluster)
        r = cluster.do_join_cluster(self.new_node(cluster),
                                    expected_code=400).json()
        assert_new_node_unknown_ca_error(r)

    def untrusted_node_joins_untrusted_cluster_test(self, cluster):
        self.provision_cluster_node(cluster)
        self.provision_new_node(cluster)
        r = cluster.do_join_cluster(self.new_node(cluster),
                                    expected_code=400).json()
        assert_new_node_unknown_ca_error(r)

    # Cluster node uses custom certs, new node uses ootb certs:

    def trusted_ootb_node_joins_trusted_cluster_test(self, cluster):
        [ca_id] = load_ca(self.cluster_node(cluster),
                          self.new_node_ootb_ca(cluster))
        load_ca(self.new_node(cluster), self.cluster_ca)
        self.provision_cluster_node(cluster)
        cluster.do_join_cluster(self.new_node(cluster))
        testlib.delete(cluster, f'/pools/default/trustedCAs/{ca_id}')

    def untrusted_ootb_node_joins_trusted_cluster_test(self, cluster):
        load_ca(self.new_node(cluster), self.cluster_ca)
        self.provision_cluster_node(cluster)
        r = cluster.do_join_cluster(self.new_node(cluster),
                                    expected_code=400).json()
        assert_cluster_unknown_ca_error(r)

    def trusted_ootb_node_joins_untrusted_cluster_test(self, cluster):
        [ca_id] = load_ca(self.cluster_node(cluster),
                          self.new_node_ootb_ca(cluster))
        self.provision_cluster_node(cluster)
        # Join works because ootb node is not validating cluster-node's certs
        cluster.do_join_cluster(self.new_node(cluster))
        testlib.delete(cluster, f'/pools/default/trustedCAs/{ca_id}')

    def untrusted_ootb_node_joins_untrusted_cluster_test(self, cluster):
        self.provision_cluster_node(cluster)
        r = cluster.do_join_cluster(self.new_node(cluster),
                                    expected_code=400).json()
        # The error happens on cluster side because the-new-node is ootb and
        # not validating cluster-node's certs
        assert_cluster_unknown_ca_error(r)

    # Cluster node uses ootb certs, new node uses custom certs:

    def trusted_node_joins_trusted_ootb_cluster_test(self, cluster):
        load_ca(self.new_node(cluster), self.cluster_ootb_ca(cluster))
        load_ca(self.cluster_node(cluster), self.new_node_ca)
        self.provision_new_node(cluster)
        cluster.do_join_cluster(self.new_node(cluster))

    def untrusted_node_joins_trusted_ootb_cluster_test(self, cluster):
        load_ca(self.new_node(cluster), self.cluster_ootb_ca(cluster))
        self.provision_new_node(cluster)
        r = cluster.do_join_cluster(self.new_node(cluster),
                                    expected_code=400).json()
        # Despite the fact that the-cluster-node is ootb, it always validates
        # new-node's certificates when doing completeJoin, so it fails on
        # the server side in this case
        assert_cluster_unknown_ca_error(r)

    def trusted_node_joins_untrusted_ootb_cluster_test(self, cluster):
        load_ca(self.cluster_node(cluster), self.new_node_ca)
        self.provision_new_node(cluster)
        r = cluster.do_join_cluster(self.new_node(cluster),
                                    expected_code=400).json()
        assert_new_node_unknown_ca_error(r)

    def untrusted_node_joins_untrusted_ootb_cluster_test(self, cluster):
        self.provision_new_node(cluster)
        r = cluster.do_join_cluster(self.new_node(cluster),
                                    expected_code=400).json()
        assert_new_node_unknown_ca_error(r)

    def provision_cluster_node(self, cluster):
        load_ca(self.cluster_node(cluster), self.cluster_ca)
        load_node_cert(self.cluster_node(cluster), self.cluster_node_cert,
                       self.cluster_node_key)

    def provision_new_node(self, cluster):
        load_ca(self.new_node(cluster), self.new_node_ca)
        load_node_cert(self.new_node(cluster), self.new_node_cert,
                       self.new_node_key)

    def cluster_node(self, cluster):
        return cluster.nodes[0]

    def new_node(self, cluster):
        return cluster.nodes[1]

    def cluster_ootb_ca(self, cluster):
        return self.get_generated_CA(self.cluster_node(cluster))

    def new_node_ootb_ca(self, cluster):
        return self.get_generated_CA(self.new_node(cluster))

    def get_generated_CA(self, node):
        CAs = testlib.get_succ(node, '/pools/default/trustedCAs').json()
        # This function assumes that there are no CA's uploaded or generated
        # because that's the only case when we need it for these ^^ tests
        assert len(CAs) == 1, 'unexpected number of CA certificates'
        assert CAs[0]['type'] == 'generated', \
               'unexpected type of CA certificate'
        return CAs[0]['pem']


def assert_cluster_unknown_ca_error(response):
    assert_msg_in_error('Unknown CA', response[0])


def assert_new_node_unknown_ca_error(response):
    assert_msg_in_error('Unknown CA', response[0])


def assert_msg_in_error(msg, error):
    assert msg in error, f'missing "{msg}" in error: "{error}"'


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
