# @author Couchbase <info@couchbase.com>
# @copyright 2024-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import random
import string

from websockets import InvalidHandshake, ConnectionClosedOK
from websockets.sync.client import connect

import testlib
from testsets.stats_tests import range_api_get


class AppTelemetryTests(testlib.BaseTestSet):
    def __init__(self, cluster):
        super().__init__(cluster)
        self.initial_prometheus_config = None
        self.initial_app_telemetry_config = None

    @staticmethod
    def requirements():
        return [testlib.ClusterRequirements(edition="Enterprise",
                                            balanced=True,
                                            min_num_nodes=2,
                                            afamily='ipv4'),
                testlib.ClusterRequirements(edition="Enterprise",
                                            balanced=True,
                                            min_num_nodes=2,
                                            afamily='ipv6')]

    def setup(self):
        self.initial_app_telemetry_config = testlib.get_succ(
            self.cluster, "/settings/appTelemetry").json()
        testlib.post_succ(self.cluster, "/settings/appTelemetry",
                          data={"enabled": "true"})
        self.initial_prometheus_config = (testlib.get_succ(
            self.cluster, "/internal/settings/metrics/services/clusterManager")
                                          .json())

        # Decrease scrape intervals to avoid having to wait long for scrape
        testlib.post_succ(self.cluster,
                          "/internal/settings/metrics/services/clusterManager",
                          data={"highCardScrapeInterval": 1})
        testlib.diag_eval(self.cluster,
                          "ns_config:set(app_telemetry,"
                          "              [{enabled, true},"
                          "               {scrape_interval_seconds, 1}]).")

    def teardown(self):
        testlib.post_succ(self.cluster, "/settings/appTelemetry",
                          json=self.initial_app_telemetry_config)
        testlib.post_succ(self.cluster,
                          "/internal/settings/metrics/services/clusterManager",
                          json=self.initial_prometheus_config)

    def simple_test(self):
        # 127.0.0.1 or [::1]
        hostname = self.cluster.connected_nodes[0].host_with_brackets

        info = testlib.get_succ(self.cluster,
                                "/pools/default/nodeServices").json()
        nodes_ext = info.get('nodesExt')
        node0_ext = nodes_ext[0]
        node0_uuid = node0_ext['nodeUUID']
        node0_services = node0_ext['services']
        node0_port = node0_services['mgmt']
        node0_host = f"{hostname}:{node0_port}"
        node0_path = node0_ext.get('appTelemetryPath')
        testlib.assert_eq('/_appTelemetry', node0_path)

        node1_ext = nodes_ext[1]
        node1_uuid = node1_ext['nodeUUID']
        node1_services = node1_ext['services']
        node1_port = node1_services['mgmt']
        node1_host = f"{hostname}:{node1_port}"

        (username, password) = self.cluster.auth
        app_telemetry_url = (f"ws://{username}:{password}@"
                             f"{hostname}:{node0_port}{node0_path}")
        with connect(app_telemetry_url) as websocket:
            message = websocket.recv(timeout=10)
            testlib.assert_eq(message, b'\x00')
            metric_0 = ''.join(random.choices(string.ascii_lowercase, k=10))
            metric_1 = ''.join(random.choices(string.ascii_lowercase, k=10))
            value = random.randrange(0, 1000000000)
            metrics = (make_metric(metric_0, node0_uuid, value) + '\n' +
                       make_metric(metric_1, node1_uuid, value))
            websocket.send(b'\x00' + metrics.encode('utf-8'))

            testlib.poll_for_condition(
                lambda:
                metric_has_value(self.cluster, {'instance': 'ns_server',
                                                'le': '0.001',
                                                'name': metric_0,
                                                'nodes': [node0_host]},
                                 value) and
                metric_has_value(self.cluster, {'instance': 'ns_server',
                                                'le': '0.001',
                                                'name': metric_1,
                                                'nodes': [node1_host]},
                                 value),
                sleep_time=1, timeout=60)

    def disabled_test(self):
        # Disable app telemetry
        testlib.post_succ(self.cluster, "/settings/appTelemetry",
                          json={"enabled": "false"})
        try:
            info = testlib.get_succ(self.cluster,
                                    "/pools/default/nodeServices").json()
            nodes_ext = info.get('nodesExt')
            node0_ext = nodes_ext[0]
            node0_path = node0_ext.get('appTelemetryPath')
            # /_appTelemetry should not be advertised
            testlib.assert_eq(None, node0_path)

            testlib.get_fail(self.cluster, "/_appTelemetry", 404)
        finally:
            # Re-enable app telemetry
            testlib.post_succ(self.cluster, "/settings/appTelemetry",
                              json={"enabled": "true"})

    def disconnect_on_disable_test(self):
        # 127.0.0.1 or [::1]
        hostname = self.cluster.connected_nodes[0].host_with_brackets

        info = testlib.get_succ(self.cluster,
                                "/pools/default/nodeServices").json()
        nodes_ext = info.get('nodesExt')
        node0_ext = nodes_ext[0]
        node0_services = node0_ext['services']
        node0_port = node0_services['mgmt']
        node0_path = node0_ext.get('appTelemetryPath')
        testlib.assert_eq('/_appTelemetry', node0_path)

        (username, password) = self.cluster.auth
        app_telemetry_url = (f"ws://{username}:{password}@"
                             f"{hostname}:{node0_port}/_appTelemetry")

        try:
            with connect(app_telemetry_url) as websocket:
                # Wait for first scrape
                websocket.recv(timeout=10)
                # Disable app telemetry
                testlib.post_succ(self.cluster, "/settings/appTelemetry",
                                  json={"enabled": "false"})
                # Since the first scrape just happened, the next scrape will be
                # after the telemetry was disabled, so it won't occur.
                # We should see the connection drop before the 10s timeout
                websocket.recv(timeout=10)
            assert False, 'expected exception is not raised'
        except AssertionError as e:
            raise e
        except Exception as e:
            assert isinstance(e, ConnectionClosedOK), \
                f'unexpected exception: {e}'
        finally:
            # Re-enable app telemetry
            testlib.post_succ(self.cluster, "/settings/appTelemetry",
                              json={"enabled": "true"})



def make_metric(metric, uuid, value):
    return (f"{metric}{{le=\"0.001\","
            f"agent=\"agent\","
            f"bucket=\"anything\","
            f"node_uuid=\"{uuid}\"}}"
            f" {value} 1695747260")


def metric_has_value(cluster, expected_metric, expected_value):
    resp = range_api_get(cluster, expected_metric['name'])
    if len(resp) > 0:
        labels = resp[0].get('metric')
        assert sorted(labels.keys()) == sorted(expected_metric.keys())
        for label in expected_metric:
            testlib.assert_eq(labels[label], expected_metric[label])
        values = resp[0].get('values')
        if len(values) > 0:
            return int(values[-1][1]) == expected_value
    return False
