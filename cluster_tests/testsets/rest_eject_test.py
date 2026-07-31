# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import testlib
from testlib.util import Service
from testlib.test_tag_decorator import tag, Tag

class RestEjectTest(testlib.BaseTestSet):
    def __init__(self, cluster):
        super().__init__(cluster)

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            num_nodes=3,
            include_services=[Service.KV],
            balanced=True,
            num_vbuckets=16,
            buckets=[{"name": "testbucket",
                      "ramQuota": 200}])

    def setup(self):
        pass

    def teardown(self):
        pass

    @tag(Tag.LowUrgency)
    def rest_reject_test(self):
        failover_node = self.cluster.connected_nodes[0]
        otp_name = failover_node.otp_node()

        self.cluster.failover_node(failover_node, graceful=False)
        # Eject failed over node via REST endpoint and verify it can be
        # added back in after ejection
        data = {"otpNode": f"{otp_name}"}
        self.cluster.eject_node(failover_node, self.cluster.connected_nodes[1])
        self.cluster.rebalance(wait=True)

        # Add node back in
        self.cluster.add_node(failover_node)
        self.cluster.rebalance(wait=True)

        # Self eject the node after failing it over again
        self.cluster.failover_node(failover_node, graceful=False)
        self.cluster.eject_node(failover_node, failover_node)
        self.cluster.rebalance(wait=True)

        # Add node back in
        self.cluster.add_node(failover_node)
        self.cluster.rebalance(wait=True)


        # The previously failed over ejected node was added back in
        # and should not be allowed to be ejected because it is active
        testlib.post_fail(self.cluster.connected_nodes[0],
                          '/controller/ejectNode',
                          expected_code=400, data=data)

    def _node_config_uuid(self, node):
        # The node's own ns_config uuid - the value that keys its
        # {local_changes_count, <uuid>} counter. Returned verbatim as an Erlang
        # term (e.g. <<"...">>) so it can be embedded back into a diag/eval.
        return testlib.diag_eval(
            node, "ns_config:uuid(ns_config:get()).").text

    def _lcc_entry(self, node, uuid_term):
        # ns_config:search result for {local_changes_count, <uuid>} on `node`:
        # "{value,...}" when the counter is present, "false" when it's absent
        # (never set, or deleted/tombstoned).
        code = ("ns_config:search(ns_config:latest(), "
                f"{{local_changes_count, {uuid_term}}}).")
        return testlib.diag_eval(node, code).text

    def _cfg_rev(self, node):
        # The ns_config half of the bucket rev: sum over all nodes of their
        # local_changes_count counters (ns_config:compute_global_rev).
        return int(testlib.diag_eval(
            node,
            "ns_config:compute_global_rev(ns_config:get()).").text)

    def _lcc_count(self, node, uuid_term):
        # count_changes of the {local_changes_count, <uuid>} counter as seen by
        # `node`, or -1 if that counter isn't present.
        code = ("case ns_config:search_with_vclock(ns_config:get(), "
                f"{{local_changes_count, {uuid_term}}}) of "
                "{value, _, {_, VC}} -> vclock:count_changes(VC); "
                "_ -> -1 end.")
        return int(testlib.diag_eval(node, code).text)

    @tag(Tag.LowUrgency)
    def local_changes_count_removed_on_eject_test(self):
        # When a node is rebalanced out of a Totoro cluster, its
        # {local_changes_count, <node-uuid>} counter must be removed from
        # ns_config (by ns_cluster_membership:remove_nodes/2). Previously these
        # keys were retained forever, so they grew unbounded across node churn.
        orchestrator = self.cluster.connected_nodes[0]
        eject_node = self.cluster.connected_nodes[-1]

        # The removal is gated on Totoro compat; a fresh cluster is at LATEST
        # (== Totoro), so this should hold.
        assert testlib.diag_eval(
            orchestrator, "cluster_compat_mode:is_cluster_totoro()."
            ).text.strip() == "true", \
            "cluster must be at Totoro compat for the counter to be removed"

        uuid = self._node_config_uuid(eject_node)

        # Give the node a sizeable local_changes_count by making many local
        # ns_config changes (each bumps its counter by 1). We make it large so a
        # rev regression caused by dropping the counter on eject can't be masked
        # by the incidental churn a rebalance adds - it would clearly exceed it.
        n_changes = 1000
        testlib.diag_eval(
            eject_node,
            "lists:foreach(fun(V) -> ns_config:set(lcc_eject_probe, V) end, "
            f"lists:seq(1, {n_changes})), ok.")

        # Wait for that counter (and its full count) to replicate to the
        # orchestrator, then snapshot the ns_config global rev.
        testlib.poll_for_condition(
            lambda: self._lcc_count(orchestrator, uuid) >= n_changes,
            sleep_time=0.3, attempts=60,
            msg="ejected node's local_changes_count to replicate before eject")
        rev_before = self._cfg_rev(orchestrator)

        # Rebalance the node out.
        self.cluster.rebalance(ejected_nodes=[eject_node], wait=True)

        # Its counter must now be gone from the surviving orchestrator's config.
        testlib.poll_for_condition(
            lambda: self._lcc_entry(orchestrator, uuid) == "false",
            sleep_time=0.3, attempts=40,
            msg="ejected node's local_changes_count removed after eject")

        # ...and the ns_config global rev must NOT go backwards across the
        # eject. Deleting the departed counter removes its count from the rev
        # (compute_global_rev skips deleted keys in Totoro), so the count must
        # be folded into a surviving node's counter - as
        # config_upgrade_to_totoro does - rather than simply dropped.
        rev_after = self._cfg_rev(orchestrator)
        assert rev_after >= rev_before, \
            f"ns_config global rev went backwards across eject: " \
            f"{rev_before} -> {rev_after}"

        # Restore the cluster to its required 3-node balanced shape.
        testlib.diag_eval(orchestrator, "ns_config:delete(lcc_eject_probe).")
        self.cluster.add_node(eject_node)
        self.cluster.rebalance(wait=True)
