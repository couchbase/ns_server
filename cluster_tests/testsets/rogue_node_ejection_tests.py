# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import time

import testlib
from testlib.requirements import Service
from testlib.test_tag_decorator import tag, Tag
from testlib.cluster import kill_nodes, get_terminal_attrs, get_node_urls, \
    get_cluster

import cluster_run_lib
import run

# ns_config key the rogue (ejected) node bumps. Matches the key used in the
# field reproduction (MB-68155).
ROGUE_KEY = "leave_test_count"

# The compat version the "rogue" node pretends to run at (below LATEST). Update
# to any version lower than LATEST as required (when we move min version
# forward).
PRETEND_VERSION = "8.0"

# Offsets used when starting the pretend-version node(s), so their ports and
# data directories don't clash with the primary cluster (or each other).
NODE_INDEX_OFFSET = 10
CLUSTER_INDEX_OFFSET = 10000


# Regression test for MB-68155.
#
# A lower-version node that was rebalanced out but got stuck in its leave
# procedure (a crash loop in ns_cluster:leave_body/0) stayed up and connected
# and kept pushing ns_config updates into the cluster it was ejected from. Once
# the cluster upgraded its compat version (which its removal enabled), those
# stale-semantics pushes could corrupt config.
class RogueNodeEjectionTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        # Primary node: a single node running at the real (LATEST) compat
        # version. This is the node that remains (and upgrades) once the
        # pretend-version node is ejected.
        return testlib.ClusterRequirements(
            edition="Enterprise",
            num_nodes=1,
            include_services=[Service.KV],
            balanced=True)

    def setup(self):
        # The pretend node is created per-test (each test ejects it), so track
        # it here and (re)build it in each test via _start_pretend_base.
        self._pretend_seq = 0
        self.pretend_cluster = None
        self.pretend_processes = None
        self.pretend_node = None

    def test_teardown(self):
        self._destroy_pretend_node()
        # Drop the rogue key from the surviving node so it doesn't leak into
        # the next test (or a reused cluster).
        testlib.diag_eval(self.cluster.connected_nodes[0],
                          f"ns_config:delete({ROGUE_KEY}).")

    def teardown(self):
        self._destroy_pretend_node()

    @tag(Tag.LowUrgency)
    def rogue_behind_revision_is_rejected_test(self):
        # This test covers the majority of the window. The node being ejected
        # will generally be behind til it observes that it should leave the
        # cluster. We will skip its update of the new topology in ns_config_rep
        # such that it pushes at the behind revision after ejection. The
        # remaining node should reject it as it is no longer in nodes_wanted and
        # the rev is `lt`.
        self._run_rogue_ejection(skip_update_nodes=True)

    @tag(Tag.LowUrgency)
    def rogue_at_ejection_revision_is_rejected_test(self):
        # This covers the last part of the window - a race on ejection in which
        # ns_config_rep may update its rev and send a merge from the node being
        # ejection before ns_config_rep is shut down. This hits the `eq` case
        # on the accept_merge path in ns_config_rep in which we still check if
        # the node remains in the cached nodes_wanted.
        self._run_rogue_ejection(skip_update_nodes=False)

    def _run_rogue_ejection(self, skip_update_nodes):
        primary_node = self.cluster.connected_nodes[0]
        self._start_pretend_base()

        # Sanity: pretend node is running at the pretended compat version.
        got = compat_version(self.pretend_node)
        assert got == pretend_compat(PRETEND_VERSION), \
            f"expected base cluster at compat {PRETEND_VERSION}, got {got}"

        # Register the primary node (and its framework-owned process) with the
        # pretend cluster object so its bookkeeping stays consistent once the
        # node joins - otherwise cluster helpers that map nodes to processes
        # raise when they encounter the newly-joined node.
        self.pretend_cluster._nodes.append(primary_node)
        self.pretend_cluster.processes.append(self.cluster.processes[0])

        # Join the LATEST primary node into the pretend-version base cluster
        # (a newer node joining an older cluster - the normal upgrade
        # direction).
        self.pretend_cluster.add_node(primary_node, services=[Service.KV],
                                      do_rebalance=True)

        nodes = testlib.get_succ(self.pretend_cluster,
                                 "/pools/default").json()["nodes"]
        assert len(nodes) == 2, \
            f"expected a 2-node cluster after the join, got {len(nodes)} " \
            f"nodes: {[n['hostname'] for n in nodes]}"

        # Sanity: the rogue key isn't set anywhere yet.
        assert config_value(primary_node, ROGUE_KEY) == "not_found"

        if skip_update_nodes:
            testlib.testconditions_set(self.pretend_node, "skip_update_nodes",
                                       "true")

        # Keep the pretend node up and connected once ejected, instead of
        # completing its leave, so it can act as the stuck rogue.
        testlib.testconditions_set(self.pretend_node, "leave_body", "stuck")

        # Rebalance the pretend-version node out. It gets stuck (stays up); the
        # surviving node then upgrades its compat version. Don't wait for the
        # ejected node to come back up - being stuck, it never resets.
        self.pretend_cluster.rebalance(ejected_nodes=[self.pretend_node],
                                       wait=True, wait_for_ejected_nodes=False)

        # Wait for the surviving node to upgrade past the pretended version.
        testlib.poll_for_condition(
            lambda: compat_version(primary_node) !=
            pretend_compat(PRETEND_VERSION),
            sleep_time=1, timeout=60,
            msg="wait for surviving node to upgrade its compat version")

        # The stuck node - still connected but ejected - pushes an ns_config
        # update to its former peer.
        testlib.diag_eval(self.pretend_node, f"ns_config:set({ROGUE_KEY}, 1).")

        observed = "not_found"
        deadline = time.time() + 15
        while time.time() < deadline:
            observed = config_value(primary_node, ROGUE_KEY)
            if observed != "not_found":
                break
            time.sleep(0.5)

        # We should not accept the merge in either the `lt` or `eq` case as
        # the node is not in nodes_wanted
        assert observed == "not_found", \
            f"MB-68155: behind ejected node pushed {ROGUE_KEY}={observed} "\
            f"into the surviving node's ns_config; it must be rejected"

    def _start_pretend_base(self):
        # Stand up an independent single node that pretends to run at an older
        # (PRETEND_VERSION) compat version, and initialise it as its own
        # cluster. This becomes the base cluster the LATEST primary node joins.
        # A distinct index/dir per invocation avoids clashing with a prior
        # test's (killed) pretend node.
        seq = self._pretend_seq
        self._pretend_seq += 1
        start_index = (self.cluster.first_node_index + NODE_INDEX_OFFSET +
                       seq * NODE_INDEX_OFFSET)
        cluster_index = self.cluster.index + CLUSTER_INDEX_OFFSET + seq
        root_dir = f"{run.tmp_cluster_dir}-{cluster_index}"

        processes = cluster_run_lib.start_cluster(
            num_nodes=1,
            start_index=start_index,
            pretend_version=PRETEND_VERSION,
            dont_rename=True,
            wait_for_start=True,
            nooutput=True,
            num_vbuckets=16,
            loglevel='critical',
            root_dir=root_dir)

        port = cluster_run_lib.base_api_port + start_index
        pretend_node = testlib.Node(host="127.0.0.1", port=port,
                                    auth=self.cluster.auth)

        # A node pinned below LATEST has the rbac_upgrade flag stuck set (it is
        # only cleared on reaching LATEST), which makes it look permanently
        # mid-upgrade and blocks cluster init. Clear it so we can initialise
        # the node into a PRETEND_VERSION cluster - this matches how a real
        # PRETEND_VERSION binary behaves (it clears the flag at its own LATEST).
        testlib.diag_eval(pretend_node, "ns_config:delete(rbac_upgrade).")

        error = cluster_run_lib.connect(num_nodes=1, start_index=start_index,
                                        create_bucket=False, do_rebalance=True,
                                        do_wait_for_rebalance=True)
        assert not error, f"failed to init pretend-version cluster: {error}"

        self.pretend_processes = processes
        self.pretend_node = pretend_node
        # Pass a copy of the process list: we later append the primary node's
        # (framework-owned) process to the cluster's list for bookkeeping, and
        # must not have that leak into self.pretend_processes, which teardown
        # uses to kill only our own node.
        self.pretend_cluster = get_cluster(
            cluster_index, port, self.cluster.auth, list(processes),
            [pretend_node], start_args={})

    def _destroy_pretend_node(self):
        if self.pretend_cluster is not None:
            kill_nodes(self.pretend_processes,
                       get_node_urls([self.pretend_node]),
                       get_terminal_attrs())
            self.pretend_cluster = None
            self.pretend_processes = None
            self.pretend_node = None


def config_value(node, key):
    # Returns the ns_config value for key as a string, or "not_found".
    return testlib.diag_eval(
        node,
        f"ns_config:search(ns_config:latest(), {key}, not_found).") \
        .text.strip()


def compat_version(node):
    # The node's current cluster compat version, e.g. "[8,0]".
    return testlib.diag_eval(
        node, "cluster_compat_mode:get_compat_version().").text.strip()


def pretend_compat(version):
    # "8.0" -> "[8,0]" to match cluster_compat_mode version formatting.
    major, minor = version.split(".")
    return f"[{int(major)},{int(minor)}]"
