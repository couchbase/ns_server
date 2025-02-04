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

import socket
from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosedOK
from websockets.uri import parse_uri
from websockets.client import ClientProtocol
from websockets.http11 import Response
from websockets.frames import Frame, Opcode

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
        testlib.assert_eq(node0_path, '/_appTelemetry')

        node1_ext = nodes_ext[1]
        node1_uuid = node1_ext['nodeUUID']
        node1_services = node1_ext['services']
        node1_port = node1_services['mgmt']
        node1_host = f"{hostname}:{node1_port}"

        (username, password) = self.cluster.auth
        app_telemetry_url = (f"ws://{username}:{password}@"
                             f"{hostname}:{node0_port}{node0_path}")

        hostname_without_brackets = self.cluster.connected_nodes[0].host
        with socket.create_connection((hostname_without_brackets, node0_port),
                                      timeout=5) as s:
            s.settimeout(5)
            protocol = ClientProtocol(parse_uri(app_telemetry_url))
            # Perform handshake
            handshake = protocol.connect()
            protocol.send_request(handshake)
            for data in protocol.data_to_send():
                s.send(data)
            # Handle handshake response
            data = s.recv(1024)
            protocol.receive_data(data)
            for data in protocol.data_to_send():
                s.send(data)
            events = protocol.events_received()
            testlib.assert_gt(len(events), 0)
            assert isinstance(events[0], Response)
            testlib.assert_eq(events[0].status_code, 101)

            # Receive initial message, if we haven't already
            if len(events) == 1:
                data = s.recv(1024)
                protocol.receive_data(data)
                for data in protocol.data_to_send():
                    s.send(data)
                events += protocol.events_received()

            # Receive GET_TELEMETRY command
            assert isinstance(events[1], Frame)
            testlib.assert_eq(events[1].opcode, Opcode.BINARY)
            testlib.assert_eq(events[1].data, b'\x00')

            # Generate metric values
            metric_0 = ''.join(random.choices(string.ascii_lowercase, k=10))
            metric_1 = ''.join(random.choices(string.ascii_lowercase, k=10))
            metric_2 = ''.join(random.choices(string.ascii_lowercase, k=10))
            value = random.randrange(0, 1000000000)
            # Test multiple lines, multiple metrics, multiple nodes, and
            # a line fragmented over multiple frames, with an interleaved ping
            frame_1 = (b'\x00' + make_metric(metric_0, node0_uuid, value) +
                       b'\n' + make_metric(metric_1, node1_uuid, value) +
                       f"\n{metric_2}{{node_uuid=".encode('utf-8'))
            frame_2 = f"\"{node0_uuid}\"}} {value} 1695747260".encode('utf-8')
            # Send the lines of metrics as a fragmented message over multiple
            # frames, with a ping interleaved
            protocol.send_binary(frame_1, fin=False)
            protocol.send_ping(b'')
            for data in protocol.data_to_send():
                s.send(data)

            # Wait for ping response
            data = s.recv(1024)
            protocol.receive_data(data)
            for data in protocol.data_to_send():
                s.send(data)
            events = protocol.events_received()
            testlib.assert_eq(len(events), 1)
            assert isinstance(events[0], Frame)
            testlib.assert_eq(events[0].opcode, Opcode.PONG)

            protocol.send_continuation(frame_2, fin=True)
            for data in protocol.data_to_send():
                s.send(data)

            # Receive second GET_TELEMETRY message, to confirm nothing crashed
            data = s.recv(1024)
            protocol.receive_data(data)
            for data in protocol.data_to_send():
                s.send(data)
            events = protocol.events_received()
            testlib.assert_eq(len(events), 1)

            # Receive GET_TELEMETRY command
            assert isinstance(events[0], Frame)
            testlib.assert_eq(events[0].opcode, Opcode.BINARY)
            testlib.assert_eq(events[0].data, b'\x00')

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
                             value) and
            metric_has_value(self.cluster, {'instance': 'ns_server',
                                            'name': metric_2,
                                            'nodes': [node0_host]},
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
            testlib.assert_eq(node0_path, None)

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
        testlib.assert_eq(node0_path, '/_appTelemetry')

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
            f" {value} 1695747260").encode('utf-8')


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
