# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import platform

import testlib
from testlib import ClusterRequirements


class NodeInfoTests(testlib.BaseTestSet):

    # Two nodes, so that a node's values are also checked as reported by the
    # other node through its heartbeat.
    @staticmethod
    def requirements():
        return ClusterRequirements(num_nodes=2, num_connected=2)

    def setup(self):
        pass

    def teardown(self):
        pass

    def node_self_test(self):
        for node in self.cluster.connected_nodes:
            poll_for_os_info(
                lambda: [testlib.get_succ(node, '/nodes/self').json()], 1)

    def pools_default_test(self):
        for node in self.cluster.connected_nodes:
            poll_for_os_info(
                lambda: testlib.get_succ(node,
                                         '/pools/default').json()['nodes'],
                2)

    def terse_cluster_info_test(self):
        poll_for_os_info(
            lambda: testlib.get_succ(self.cluster,
                                     '/pools/default/terseClusterInfo',
                                     params={'nodes': 'true'}).json()['nodes'],
            2)


# A node's info comes from its heartbeat, which may not have arrived yet on a
# freshly started cluster.
def poll_for_os_info(get_nodes, num_nodes):
    def check():
        nodes = get_nodes()
        testlib.assert_eq(len(nodes), num_nodes)
        for info in nodes:
            assert_os_info(info)
        return True
    testlib.poll_for_condition(check, sleep_time=0.5, timeout=30,
                               retry_on_assert=True, msg='poll for os info')


# cluster_run nodes run on this machine, so expect what it reports.
def assert_os_info(info):
    os_name = info.get('osName')
    if platform.system() == 'Linux':
        testlib.assert_eq(os_name, linux_os_name())
    else:
        assert os_name not in (None, '', 'unknown'), \
            f'unexpected osName {os_name!r} in {info}'
    testlib.assert_eq(info.get('osKernel'), platform.release())


# Not platform.freedesktop_os_release(), which reports "Linux" when the name
# fields are missing, where ns_server reports "unknown". Some containers have
# no usable os-release at all.
def linux_os_name():
    for path in ('/etc/os-release', '/usr/lib/os-release'):
        try:
            with open(path, encoding='utf-8') as f:
                lines = f.read().split('\n')
        except OSError:
            continue
        props = {k: v.strip('"\'') for k, v in
                 (line.split('=', 1) for line in lines if '=' in line)}
        # As in ns_server, values are trimmed, an empty value counts as
        # missing, and VERSION without a name gives "unknown".
        pretty_name = props.get('PRETTY_NAME', '').strip()
        if pretty_name:
            return pretty_name
        name = props.get('NAME', '').strip()
        if not name:
            return 'unknown'
        version = props.get('VERSION', '').strip()
        return f'{name} {version}' if version else name
    return 'unknown'
