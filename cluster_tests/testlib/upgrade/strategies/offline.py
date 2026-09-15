# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Offline upgrade: stop the whole cluster, bring it back on the new release.

The nodes are upgraded in place -- the same data directories, different
binaries -- so each climbs ns_config_default:upgrade_config/1, the config
ladder a node climbs as it boots on a release newer than the one that wrote
its config. Coming from 7.6 that means every rung from 7.2 up, in a single
boot, and all nodes at once.

There is no mixed cluster at any point, and the interface says so by having
no mixed callback: a suite running under this strategy is never asked a
question it cannot answer, rather than being asked and skipped.
"""

from abc import ABC, abstractmethod

from testlib.upgrade.strategy import UpgradeStrategy, callback, transition


class OfflineUpgradeSuite(ABC):
    """The callbacks an offline upgrade invokes on a suite.

    Two, not three. An offline upgrade never has both versions running, so
    there is nothing to ask in between; a suite whose checks only mean
    something across a version boundary simply does not declare this
    interface.
    """

    @abstractmethod
    def before_upgrade(self):
        """Only the source version is present. Capture what you compare."""

    @abstractmethod
    def post_upgrade_checks(self):
        """Only the version under test remains."""


class OfflineUpgrade2Node(UpgradeStrategy):
    """Two nodes, stopped and restarted on the version under test."""

    name = 'offline-2node'
    suite_base = OfflineUpgradeSuite
    old_node_count = 2
    # No replacements: the nodes that come back up are the nodes that went
    # down, so this strategy runs half the processes a swap-rebalance one
    # does.
    new_node_count = 0

    def stages(self):
        return [
            callback('before_upgrade'),
            transition('stop-cluster-and-restart-on-new-version',
                       self.upgrade_in_place),
            callback('post_upgrade_checks'),
        ]

    def upgrade_in_place(self, ctx):
        # Down and up has to be one transition. The harness logs to every
        # node between tests, so splitting this would leave a test boundary
        # with the cluster down and report that as a pile of failures having
        # nothing to do with the upgrade.
        ctx.cluster.upgrade_all_nodes_in_place()
        # The same nodes, on the new release: that is what in place means.
        ctx.nodes_upgraded(ctx.old_nodes)
        # Before verify(), so a failed check cannot leave the capability
        # flags describing the old compat mode.
        ctx.wait_for_compat_bump()
        ctx.verify(mixed=False)
