# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Upgrade by graceful failover, in-place restart and delta recovery.

A node is failed over gracefully, restarted on the new release keeping its
data, then delta-recovered -- so it rejoins with the data it already had
instead of resyncing the lot. That is how a cluster is upgraded without
either the downtime an offline upgrade costs or the spare hardware a swap
rebalance needs, and it is the only path here where a node leaves the
cluster and comes back as itself.

Like an online upgrade it passes through a mixed cluster, so it offers the
same three callbacks; unlike one, the two versions are the same nodes at
different times rather than different nodes.
"""

from abc import ABC, abstractmethod

from testlib.upgrade.strategy import UpgradeStrategy, callback, transition


class DeltaRecoveryUpgradeSuite(ABC):
    """The callbacks a delta-recovery upgrade invokes on a suite.

    The same three an online upgrade offers, and they mean the same thing. A
    suite still declares this separately, so that one which cannot cope with
    a node briefly leaving the cluster can decline delta recovery while
    still running online.
    """

    @abstractmethod
    def before_upgrade(self):
        """Only the source version is present. Capture what you compare."""

    @abstractmethod
    def mixed_cluster_checks(self):
        """Some nodes are upgraded and some are not; both are serving."""

    @abstractmethod
    def post_upgrade_checks(self):
        """Only the version under test remains."""


class DeltaRecoveryUpgrade2Node(UpgradeStrategy):
    """Two nodes, each failed over, upgraded in place and delta-recovered."""

    name = 'delta-2node'
    suite_base = DeltaRecoveryUpgradeSuite
    old_node_count = 2
    # The upgraded nodes are the original nodes, so no replacements are
    # started: this runs N node processes, as the offline strategy does.
    new_node_count = 0

    def stages(self):
        return [
            callback('before_upgrade'),
            transition('failover-upgrade-and-delta-recover-one-node',
                       self.upgrade_one_node),
            callback('mixed_cluster_checks'),
            transition('failover-upgrade-and-delta-recover-the-rest',
                       self.upgrade_remaining_nodes),
            callback('post_upgrade_checks'),
        ]

    def upgrade_one_node(self, ctx):
        # The last node, deliberately: a suite's old_node is old_nodes[0],
        # so leaving the first node alone means the mixed callback has a
        # node on each version to compare.
        self.upgrade(ctx, ctx.old_nodes[-1])
        ctx.verify(mixed=True)

    def upgrade_remaining_nodes(self, ctx):
        for node in ctx.old_nodes[:-1]:
            self.upgrade(ctx, node)
        # Before verify(), so a failed check cannot leave the capability
        # flags describing the old compat mode.
        ctx.wait_for_compat_bump()
        ctx.verify(mixed=False)

    def upgrade(self, ctx, node):
        cluster = ctx.cluster
        cluster.failover_node(node, graceful=True)
        cluster.upgrade_node_in_place(node)
        # recover_node, and nothing between: it sets the recovery type
        # before it rebalances. A rebalance while the node is still
        # inactiveFailed would drop it from connected_nodes -- Cluster
        # .rebalance folds every failed-over node into the ejected set to
        # keep its own bookkeeping straight -- and the node being recovered
        # would disappear from the harness's view of the cluster while the
        # server carried on holding it.
        cluster.recover_node(node, recovery_type='delta', do_rebalance=True)
        ctx.nodes_upgraded([node])
