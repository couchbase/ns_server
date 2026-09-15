# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Online upgrade: swap replacement nodes in, then rebalance the old ones out.

The cluster stays up throughout and never drops below its full complement of
nodes: the replacements join first, so the mixed cluster is the original
cluster plus the new nodes, and only then do the old ones leave. That makes it
the one kind of upgrade where a suite can compare the two versions side by
side, which is what mixed_cluster_checks is for.
"""

from testlib.upgrade.strategy import UpgradeStrategy, callback, transition


class OnlineUpgrade2to2(UpgradeStrategy):
    """Two nodes, replaced by two."""

    name = 'online-2to2'
    old_node_count = 2
    new_node_count = 2

    def stages(self):
        return [
            callback('before_upgrade'),
            transition('add-new-nodes-and-rebalance-in', self.rebalance_in),
            callback('mixed_cluster_checks'),
            transition('rebalance-out-old-nodes', self.rebalance_out),
            callback('post_upgrade_checks'),
        ]

    def rebalance_in(self, ctx):
        new_nodes = ctx.start_new_nodes(self.new_node_count)
        # Join each replacement with the same services as the node it stands
        # in for, rather than relying on add_node's default, which takes the
        # services of whichever connected node handles the request.
        for old_node, new_node in zip(ctx.old_nodes, new_nodes):
            ctx.cluster.add_node(new_node, services=old_node.get_services())
        ctx.cluster.rebalance(wait=True)
        ctx.verify(mixed=True)

    def rebalance_out(self, ctx):
        ctx.cluster.rebalance(ejected_nodes=list(ctx.old_nodes), wait=True,
                              verbose=True, node=ctx.new_nodes[0])
        # Before verify(), so a failed check cannot leave the capability
        # flags describing the old compat mode.
        ctx.wait_for_compat_bump()
        ctx.verify(mixed=False)
