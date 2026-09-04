# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

from pathlib import Path

import testlib
from testlib.requirements import Service
from testlib.test_tag_decorator import tag, Tag
from testsets.node_addition_tests import assert_cluster_size
from testsets.rogue_node_ejection_tests import STUCK_LEAVE_KEY

BUCKET_NAME = "leave-marker-test"

# Marker ns_cluster:leave_init/0 writes under the data dir before it starts
# tearing the node down.
LEAVE_MARKER = "leave_marker"

# A node that crashes part way through leaving the cluster restarts with the
# leave marker still on disk. ns_cluster:init/1 finds it and casts itself
# `leave`, so leave_body/0 runs the moment init returns. This can happen while
# ns_server_cluster_sup is still starting the children specified after
# ns_cluster.
#
# Test that we can handle this.
class LeaveMarkerStartupTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            edition="Enterprise",
            num_nodes=2,
            num_connected=2,
            include_services=[Service.KV],
            buckets=[{"name": BUCKET_NAME, "ramQuota": 100}],
            balanced=True)

    def setup(self):
        self.victim = None
        self.victim_data_path = None

    def teardown(self):
        pass

    def test_teardown(self):
        self.restore_victim()

        assert_cluster_size(self.cluster, 2)
        self.cluster.wait_nodes_up()

    def restore_victim(self):
        victim = self.victim
        marker = self.victim_data_path / LEAVE_MARKER

        try:
            testlib.wait_for_ejected_node(victim)
        except AssertionError:
            print(f"Node {victim} did not come back up. Removing {marker} "
                  f"and restarting it so the rest of the run can continue")
            marker.unlink(missing_ok=True)
            restart_without_waiting(self.cluster, victim)
            testlib.wait_for_ejected_node(victim)

        # Clean up the key that blocks the leave just in case the test failed
        testlib.delete_config_key(victim, STUCK_LEAVE_KEY)

        if victim not in self.cluster.connected_nodes:
            self.cluster.add_node(victim, services=[Service.KV])
            self.cluster.rebalance(wait=True)

    @tag(Tag.LowUrgency)
    def leave_marker_found_on_startup_test(self):
        victim = self.cluster.connected_nodes[1]
        self.victim = victim

        data_path = Path(victim.data_path())
        bucket_dir = (Path(victim.dbdir()) /
                      self.cluster.get_bucket_uuid(BUCKET_NAME))
        self.victim_data_path = data_path

        marker = data_path / LEAVE_MARKER
        assert not marker.exists(), f"stale leave marker at {marker}"

        # Park the victim part way through its leave. It keeps the marker and
        # its bucket data, which is the on-disk state a node is left in when it
        # crashes mid-leave.
        testlib.diag_eval(victim, f"ns_config:set({STUCK_LEAVE_KEY}, stuck).")

        self.cluster.rebalance(ejected_nodes=[victim], wait=True,
                               wait_for_ejected_nodes=False)

        testlib.poll_for_condition(
            marker.exists, sleep_time=0.5, timeout=60,
            msg=f"wait for leave marker at {marker}")
        assert bucket_dir.exists(), \
            f"stuck node lost its bucket data at {bucket_dir} before restart"

        # Clear the condition, so the restarted node completes its leave rather
        # than parking again
        testlib.delete_config_key(victim, STUCK_LEAVE_KEY)

        # ns_cluster:init/1 finds the marker on the way up and completes the
        # leave from there. A node that crashes instead never serves REST
        # again, so coming up at all is the pass condition.
        restart_without_waiting(self.cluster, victim)
        testlib.wait_for_ejected_node(victim)

        assert not marker.exists(), f"leave marker {marker} was not removed"


# Cluster.restart_node inherits wait_for_start from the cluster's start args
# and raises on timeout. A node that never completes its leave never comes up,
# and that is the outcome under test, so wait for it here instead.
def restart_without_waiting(cluster, node):
    saved = cluster.start_args.get("wait_for_start")
    cluster.start_args["wait_for_start"] = False
    try:
        cluster.restart_node(node)
    finally:
        cluster.start_args["wait_for_start"] = saved
