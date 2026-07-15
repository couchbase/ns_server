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
from testlib.test_tag_decorator import tag, Tag
from testlib.util import Service


class ServicesTopologyTests(testlib.BaseTestSet):

    def setup(self):
        self.old_mem_quotas = {}
        self.otp_nodes = [node.otp_node()
                          for node in self.cluster.connected_nodes]
        self.failed_node = None

    def teardown(self):
        pass

    def test_teardown(self):
        if self.failed_node != None:
            self.cluster.recover_node(
                self.failed_node, recovery_type="full", do_rebalance=True)
            self.failed_node = None

        self.restore_service_quotas()
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
                                    include_services= topology)]

    def otp_node(self, index):
        return self.otp_nodes[index]

    def get_topology(self):
        resp = testlib.get_succ(self.cluster, "/pools/default")
        return {node["otpNode"]: set(node["services"])
                for node in resp.json()["nodes"]}

    def assert_topology(self, topology):
        expected = {self.otp_node(k):
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
            node = self.otp_node(n)
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
        expected = set([self.otp_node(n) for n in node_indexes])

        assert actual == expected, \
            f"Incorrect map for the service {service} " \
            f"Expected: {expected}, Actual: {actual}"

    def change_services_topology(self, topology, expected_code):
        services = topology.keys()
        return self.rebalance(topology, services, expected_code)

    def rebalance(self, topology, services, expected_code):
        data = {}
        if services != None:
            data['services'] = ','.join([s.value for s in services]),

        for service, node_indexes in topology.items():
            otp_nodes = [self.otp_node(n) for n in node_indexes]
            data[f"topology[{service.value}]"] = ','.join(otp_nodes)

        res = self.rebalance_with_params(data, expected_code)

        if res.status_code == 200:
            self.assert_service_map(service, node_indexes)
        return res

    def rebalance_with_params(self, params, expected_code):
        known_nodes = [self.otp_node(n) for n in [0, 1, 2]]
        data = {'knownNodes': ','.join(known_nodes),
                'ejectedNodes': ""}

        res = testlib.post_succ(self.cluster, "/controller/rebalance",
                                data=data | params, expected_code=expected_code)

        if res.status_code == 200:
            # The cluster should be balanced after the rebalance
            self.cluster.wait_for_rebalance(wait_balanced=True)
        return res

    def set_service_quota(self, service, quota, json):
        key = testlib.util.service_to_memory_quota_key(service)
        if json is not None:
            self.old_mem_quotas[service] = json[key]
        testlib.post_succ(self.cluster, "/pools/default", data = {key: quota})

    def restore_service_quotas(self):
        for service, quota in self.old_mem_quotas.items():
            self.set_service_quota(service, quota, None)
        self.old_mem_quotas = {}

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

    @tag(Tag.LowUrgency)
    def serviceless_node_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.change_services_topology({Service.INDEX: [0], Service.QUERY: [2]},
                                      200)
        self.assert_topology([[Service.KV, Service.INDEX],
                              [],
                              [Service.QUERY]])

    @tag(Tag.LowUrgency)
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

    def set_large_quotas(self):
        resp = testlib.get_succ(self.cluster, "/pools/default")
        json = resp.json()
        memtotal = resp.json()["nodes"][0]["memoryTotal"] / (1024 * 1024)
        kvquota = json["memoryQuota"]
        newquota = int((memtotal - kvquota) / 2 + 500)

        self.set_service_quota(Service.INDEX, newquota, json)
        self.set_service_quota(Service.FTS, newquota, json)

    def enough_quota_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.set_large_quotas()
        self.change_services_topology({Service.FTS: [2]}, 200)

    def exceed_quota_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.set_large_quotas()

        self.change_services_topology({Service.FTS: [0]}, 400)
        self.assert_topology(ServicesTopologyTests.initial_topology)

    def swap_services_with_large_quotas_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.set_large_quotas()

        self.change_services_topology({Service.FTS: [2]}, 200)

        # Since the swap is not atomic we cannot guarantee that the quota
        # will not be exceeded on one of the nodes if the operation is
        # interrupted. So even if in the success case the quota is not
        # exceeded, we have to deny this
        res = self.change_services_topology(
            {Service.FTS: [0], Service.INDEX: [2]}, 400)
        json = testlib.json_response(res,
                                     testlib.format_error(res, "Invalid json"))
        testlib.assert_json_key("total_quota_too_high", json,
                                testlib.format_res_info(res))

    @tag(Tag.LowUrgency)
    def full_rebalance_test(self):
        self.assert_topology(ServicesTopologyTests.initial_topology)
        self.rebalance({Service.BACKUP: [1, 2]}, None, 200)
        self.assert_topology([[Service.KV, Service.INDEX],
                              [Service.QUERY, Service.INDEX, Service.BACKUP],
                              [Service.QUERY, Service.BACKUP]])

    def not_rebalancing_service_test(self):
        res = self.rebalance({Service.BACKUP: [1, 2]}, [Service.INDEX], 400)
        testlib.assert_eq(res.text,
                          'Not all services with new topology are included'
                          ' in the rebalance')
        self.assert_topology(ServicesTopologyTests.initial_topology)

    def delta_recovery_test(self):
        failover_node = self.cluster.connected_nodes[1]
        self.failed_node = failover_node
        self.cluster.failover_node(failover_node, graceful=False)
        self.cluster.recover_node(
            failover_node, recovery_type="delta", do_rebalance=False)
        res = self.change_services_topology({Service.BACKUP: [2]}, 400)
        testlib.assert_eq(res.text, 'Service topology change is incompatible '
                          'with delta recovery')

    def failed_node_test(self):
        failover_node = self.cluster.connected_nodes[1]
        self.failed_node = failover_node
        self.cluster.failover_node(failover_node, graceful=False)
        res = self.change_services_topology({Service.BACKUP: [2]}, 400)
        testlib.assert_eq(res.text, 'Service topology change is not possible if'
                          ' some nodes are failed over')

    def kv_not_allowed_test(self):
        res = self.change_services_topology({Service.KV: [1, 2]}, 400)
        testlib.assert_eq(res.text, 'Cannot change topology for data service')

    def bad_parameters_test(self):
        nodes_str = ','.join(self.otp_nodes)
        res = self.rebalance_with_params({"topology": nodes_str}, 400)
        testlib.assert_eq(res.text, 'Malformed topology parameter "topology"')

        res = self.rebalance_with_params({"topology[aa,bb]": nodes_str}, 400)
        testlib.assert_eq(
            res.text, 'Malformed topology parameter "topology[aa,bb]"')

        res = self.rebalance_with_params({"topology[wrong]": nodes_str}, 400)
        testlib.assert_eq(res.text, 'Unknown service "wrong"')

        res = self.rebalance_with_params({"topology[index]": "wrong"}, 400)
        testlib.assert_eq(res.text, 'Unknown or ejected nodes ["wrong"]')

        res = self.rebalance_with_params({"topology[index]": nodes_str,
                                          "services": "backup"}, 400)

def parse_nodes_list(text):
    sansbrackets = text.strip(" \n[]")
    if sansbrackets == '':
        return []
    return [v.strip(" \n'") for v in sansbrackets.split(",")]


class SingleNodeServiceTopologyTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            edition="Enterprise",
            afamily="ipv4",
            encryption=False,
            memsize=256,
            num_nodes=1,
            num_connected=1,
            include_services=[Service.KV],
            balanced=True)

    def setup(self):
        # Remember the memory quota so we can restore it after hard resetting.
        self.memory_quota = self.cluster.memory_quota()

    def teardown(self):
        pass

    def test_teardown(self):
        node = self.cluster.connected_nodes[0]

        testlib.post_succ(node, "/controller/hardResetNode")
        wait_hard_reset_node_up(node)

        # Restore everything to match cluster described in requirements()
        data = {'afamily': "ipv4",
                'hostname': node.host,
                'nodeEncryption': "off",
                'memoryQuota': 256,
                'port': "SAME",
                'username': self.cluster.admin_user(),
                'password': self.cluster.admin_password(),
                'services': "kv"}
        testlib.post_succ(node, f"/clusterInit", data=data).json()

        def check_node_ready():
            r = testlib.get(node, "/pools/default")
            return r.status_code == 200

        testlib.poll_for_condition(check_node_ready, sleep_time=5, timeout=300,
                                   msg="wait for node to be ready")

    def provision_without_services(self, node):
        # Provision the node without going through setupServices: just set a
        # memory quota and the credentials (which makes the system provisioned).
        # Order mirrors /clusterInit: the memory quota is set first (no web
        # server restart), credentials last (/settings/web restarts the web
        # server but only replies once it is back up).
        testlib.post_succ(node, "/pools/default",
                          data={"memoryQuota": self.memory_quota})
        testlib.post_succ(node, "/settings/web",
                          data={"port": "SAME",
                                "username": self.cluster.admin_user(),
                                "password": self.cluster.admin_password()})

    def node_services(self, node):
        return node.get_services(use_cache=False)

    # Regression test for MB-72855.
    #
    # When chronicle is provisioned from scratch (chronicle_upgrade:initialize/0
    # - which happens e.g. after a hard reset) the node's membership is set to
    # 'active' but its {node, Node, services} key is never written; readers rely
    # on ns_cluster_membership:node_services/2 defaulting to default_services()
    # ([kv]). If such a node is then provisioned without going through
    # setupServices (just credentials + memory quota), it ends up system
    # provisioned but with no services key in chronicle.
    #
    # A subsequent service topology rebalance used to crash in
    # add_service_nodes_sets/3 with {badkey, {node, Node, services}} because it
    # read the key with a raw maps:get/2 instead of the defaulting reader.
    def topology_change_without_setupservices_test(self):
        node = self.cluster.connected_nodes[0]

        # Hard reset wipes chronicle and clears the credentials. On restart the
        # node re-provisions chronicle via chronicle_upgrade:initialize/0, which
        # sets membership=active but leaves the services key unset.
        testlib.post_succ(node, "/controller/hardResetNode")
        wait_hard_reset_node_up(node)

        # Re-provision the node WITHOUT setupServices: just credentials and a
        # memory quota. This reproduces the MB-72855 state (system provisioned,
        # membership active, no services key) without touching chronicle
        # directly.
        self.provision_without_services(node)

        testlib.assert_eq(self.node_services(node), [Service.KV],
                          "node services")

        # Add a topology aware service (n1ql needs no memory quota) via a
        # rebalance. Prior to the fix add_service_nodes_sets/3 crashed here with
        # {badkey, {node, Node, services}} and the rebalance failed.
        otp = node.otp_node()
        testlib.post_succ(node, "/controller/rebalance",
                          data={"knownNodes": otp,
                                "ejectedNodes": "",
                                f"topology[{Service.QUERY.value}]": otp})
        # wait_for_rebalance returns an error string (not raise) if the
        # rebalance failed, so check it explicitly - that's where the MB-72855
        # crash surfaces.
        err = self.cluster.wait_for_rebalance(wait_balanced=True)
        assert err is None, f"rebalance to add n1ql failed: {err}"

        # The service was added and the key now exists in chronicle.
        assert Service.QUERY in self.node_services(node), \
            f"n1ql missing after rebalance: {self.node_services(node)}"


def wait_hard_reset_node_up(node):
    # After a hard reset the node leaves the cluster and restarts its web
    # server. Wait until it is up again and reports as uninitialized.
    def node_is_up():
        try:
            resp = testlib.get(node, '/pools/default')
            return resp.status_code == 404 and '"unknown pool"' == resp.text
        except Exception as e:
            print(f'got exception: {e}')
            return False

    testlib.poll_for_condition(
        node_is_up, sleep_time=1, timeout=60,
        msg=f'wait for hard reset node {node} to be up')
