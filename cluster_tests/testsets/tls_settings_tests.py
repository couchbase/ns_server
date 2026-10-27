# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import socket
import sys

import testlib
from testlib.util import Service

sys.path.append(testlib.get_scripts_dir())
from tls_groups import discover_tls13_groups

SERVICES = [Service.KV, Service.INDEX, Service.QUERY, Service.FTS,
            Service.EVENTING, Service.BACKUP]


class TLSSettingsTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        # TLS dist listener is started only when encryption is enabled
        return testlib.ClusterRequirements(
                 edition='Enterprise', encryption=True,
                 include_services=SERVICES)

    def setup(self):
        pass

    def teardown(self):
        pass

    def rest_tls_groups_test(self):
        for node in self.cluster.connected_nodes:
            assert_hybrid_groups_preferred(node, node.tls_service_port())

    def capi_tls_groups_test(self):
        for node in self.cluster.connected_nodes:
            assert_hybrid_groups_preferred(
                node, node.tls_service_port(Service.VIEWS))

    def dist_tls_groups_test(self):
        for node in self.cluster.connected_nodes:
            assert_hybrid_groups_preferred(node,
                                           node.otp_port(encryption=True))

    def kv_tls_groups_test(self):
        self.check_service_tls_groups(Service.KV)

    def index_tls_groups_test(self):
        self.check_service_tls_groups(Service.INDEX)

    def query_tls_groups_test(self):
        self.check_service_tls_groups(Service.QUERY)

    def fts_tls_groups_test(self):
        self.check_service_tls_groups(Service.FTS)

    def eventing_tls_groups_test(self):
        self.check_service_tls_groups(Service.EVENTING)

    def backup_tls_groups_test(self):
        self.check_service_tls_groups(Service.BACKUP)

    def check_service_tls_groups(self, service):
        nodes = [n for n in self.cluster.connected_nodes
                 if service in n.get_services()]
        assert nodes, f'No nodes with {service}'
        for node in nodes:
            port = node.tls_service_port(service)
            # Services might still be starting
            testlib.poll_for_condition(
                lambda: is_listening(node.host, port), sleep_time=1,
                timeout=60, msg=f'wait for {service} on {node.host}:{port}')
            assert_hybrid_groups_preferred(node, port)


def is_listening(host, port):
    try:
        socket.create_connection((host, port), timeout=5).close()
        return True
    except ConnectionRefusedError:
        return False


def assert_hybrid_groups_preferred(node, port):
    report = discover_tls13_groups(node.host, port)
    where = f'{node.host}:{port}'
    names = [g.name for g in report.supported]

    assert not report.failing, \
        f'TLS handshake fails on {where} for groups: {report.failing}'
    assert not report.unordered, \
        f'Priority of {report.unordered} is undetermined on {where}'

    kinds = [g.kind for g in report.supported]
    assert 'hybrid' in kinds, f'No hybrid groups supported on {where}: {names}'
    assert 'post_quantum' not in kinds, \
        f'Pure post-quantum groups are supported on {where}: {names}'
    num_hybrid = kinds.count('hybrid')
    assert kinds[:num_hybrid] == ['hybrid'] * num_hybrid, \
        f'Hybrid groups are not first on {where}: {names}'

    # Hybrid groups must be preferred by the server, not only when the client
    # happens to list them first
    for tier in report.tiers:
        assert len({g.kind for g in tier}) == 1, \
            f'Server on {where} lets the client choose between ' \
            f'{[g.name for g in tier]}'
