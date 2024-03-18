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
import functools

from testlib import ClusterRequirements
from testlib.util import Service


class ServicesTopologyTests(testlib.BaseTestSet):

    def setup(self):
        pass

    def teardown(self):
        pass

    def test_teardown(self):
        self.restore_initial_topology()

    initial_topology = [[Service.KV, Service.INDEX],
                        [Service.QUERY, Service.INDEX],
                        [Service.QUERY]]

    @staticmethod
    def requirements():
        topology = {f"n{k}": v for k, v in
                    enumerate(ServicesTopologyTests.initial_topology)}
        return [ClusterRequirements(edition="Serverless",
                                    balanced=True, num_nodes=3, num_connected=3,
                                    services = topology)]

    def get_topology(self):
        resp = testlib.get_succ(self.cluster, "/pools/default")
        return {node["otpNode"]: set(node["services"])
                for node in resp.json()["nodes"]}

    def assert_topology(self, topology):
        expected = {self.cluster.otp_node(k):
                    set(testlib.util.services_to_strings(v))
                    for k, v in list(enumerate(topology))}
        actual = self.get_topology()
        assert actual == expected, \
            f"Wrong services topology in cluster. Expected {expected}, " \
            f"Actual {actual}"

    def restore_initial_topology(self):
        current = {k: set(testlib.util.strings_to_services(v))
                   for k, v in self.get_topology().items()}
        services = set()
        for n, s in enumerate(ServicesTopologyTests.initial_topology):
            node = self.cluster.otp_node(n)
            diff = current[node].symmetric_difference(set(s))
            services.update(diff)

        topology = {}
        for s in services:
            nodes = []
            for n, slist in enumerate(ServicesTopologyTests.initial_topology):
                if s in slist:
                    nodes.append(n)
            topology[s] = nodes

        if len(topology) > 0:
            self.change_services_topology(topology, 200)

        self.assert_topology(ServicesTopologyTests.initial_topology)

    def assert_service_map(self, service, node_indexes):
        res = testlib.diag_eval(
            self.cluster,
            f"ns_cluster_membership:get_service_map(direct, "
            f"{service.value}).")

        actual = set(parse_nodes_list(res.content.decode('ascii')))
        expected = set([self.cluster.otp_node(n) for n in node_indexes])

        assert actual == expected, \
            f"Incorrect map for the service {service} " \
            f"Expected: {expected}, Actual: {actual}"

    def change_services_topology(self, topology, expected_code):
        known_nodes = [self.cluster.otp_node(n) for n in [0, 1, 2]]
        services = [s.value for s in topology.keys()]
        data = {'knownNodes': ','.join(known_nodes),
                'services': ','.join(services),
                'ejectedNodes': ""}

        for service, node_indexes in topology.items():
            otp_nodes = [self.cluster.otp_node(n) for n in node_indexes]
            data[f"topology[{service.value}]"] = ','.join(otp_nodes)

        res = testlib.post_succ(self.cluster, "/controller/rebalance",
            data=data, expected_code=expected_code)

        if res.status_code == 200:
            self.cluster.wait_for_rebalance()
            self.assert_service_map(service, node_indexes)
        return res

    def topology_aware_service_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.assert_service_map(Service.INDEX, [0, 1])
        self.change_services_topology({Service.INDEX: [1, 2]}, 200)
        self.assert_topology([[Service.KV],
                              [Service.QUERY, Service.INDEX],
                              [Service.QUERY, Service.INDEX]])

    def new_topology_aware_service_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.assert_service_map(Service.EVENTING, [])
        self.change_services_topology({Service.EVENTING: [1, 2]}, 200)
        self.assert_topology([[Service.KV, Service.INDEX],
                              [Service.QUERY, Service.INDEX, Service.EVENTING],
                              [Service.QUERY, Service.EVENTING]])

    def remove_topology_aware_service_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.assert_service_map(Service.INDEX, [0, 1])
        self.change_services_topology({Service.INDEX: []}, 200)
        self.assert_topology([[Service.KV],
                              [Service.QUERY],
                              [Service.QUERY]])

    def serviceless_node_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.change_services_topology({Service.INDEX: [0], Service.QUERY: [2]},
                                      200)
        self.assert_topology([[Service.KV, Service.INDEX],
                              [],
                              [Service.QUERY]])

    def simple_service_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.assert_service_map(Service.BACKUP, [])
        self.change_services_topology({Service.BACKUP: [1, 2]}, 200)
        self.assert_topology([[Service.KV, Service.INDEX],
                              [Service.QUERY, Service.INDEX, Service.BACKUP],
                              [Service.QUERY, Service.BACKUP]])
        self.change_services_topology({Service.BACKUP: [0, 1]}, 200)
        self.assert_topology([[Service.KV, Service.INDEX, Service.BACKUP],
                              [Service.QUERY, Service.INDEX, Service.BACKUP],
                              [Service.QUERY]])

def parse_nodes_list(text):
    sansbrackets = text.strip("[").strip("]")
    if sansbrackets == '':
        return []
    return [v.strip("'") for v in sansbrackets.split(",")]
