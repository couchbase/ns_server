# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""What an upgrade strategy is, and what it is handed.

A strategy is one kind of upgrade -- an online swap rebalance, an offline
in-place restart, a graceful failover with delta recovery -- and it owns the
three things the engine deliberately does not know:

    how many nodes it needs, and how many replacements it brings up,
    the transitions that actually move the cluster,
    the callbacks it invokes on the suites in between.

The engine walks stages() and knows nothing else about any particular
strategy, so another kind of upgrade is another module under strategies/ and
no change here or in the engine.

Callback names belong to the strategy rather than to this module. An online
3-to-3 strategy is free to offer before_upgrade, first_node_replaced,
second_node_replaced and third_node_replaced; nothing here says otherwise.
"""

import collections
from abc import ABC, abstractmethod

import testlib

CALLBACK = 'callback'
TRANSITION = 'transition'

Stage = collections.namedtuple('Stage', ['kind', 'name', 'fn'])


def callback(name):
    """A point in the cycle where every suite's `name` hook is called.

    Each suite's hook is reported as its own test, so one suite failing here
    costs no other suite its verdict.
    """
    return Stage(CALLBACK, name, None)


def transition(name, fn):
    """A step that moves the cluster. `fn` is called with the UpgradeContext.

    A transition is reported as a single test and must be atomic: the harness
    logs to every node between tests, so a transition may not leave a node
    down at its own boundary. Anything that takes a node down has to bring it
    back up within the same transition.
    """
    return Stage(TRANSITION, name, fn)


def compat_mode_of(cluster):
    """The cluster's compat mode as a string, e.g. '8.0'."""
    pools = testlib.get_succ(cluster, "/pools/default").json()
    modes = set()
    for node in pools["nodes"]:
        compat = node["clusterCompatibility"]
        modes.add(f"{compat >> 16}.{compat & 0xFFFF}")
    assert len(modes) == 1, f"expected a single compat mode, got {modes}"
    return modes.pop()


def verify_cluster(cluster, mixed):
    """Assert the cluster is healthy and balanced; return its compat mode.

    With mixed=True exactly two node versions must be present, otherwise one.
    """
    pools = testlib.get_succ(cluster, "/pools/default").json()
    # Carried by every assertion below rather than printed: what each node
    # is running is the first thing wanted when one of these fails, and of
    # no interest at all when they pass.
    nodes = "\n  ".join(
        f"{node['hostname']} version={node['version']} "
        f"compat={node['clusterCompatibility'] >> 16}."
        f"{node['clusterCompatibility'] & 0xFFFF} "
        f"status={node['status']} membership={node['clusterMembership']}"
        for node in pools["nodes"])

    assert pools["balanced"], f"cluster is not balanced:\n  {nodes}"
    for node in pools["nodes"]:
        assert node["status"] == "healthy", \
            f"{node['hostname']} is {node['status']}:\n  {nodes}"
        assert node["clusterMembership"] == "active", \
            f"{node['hostname']} is {node['clusterMembership']}:\n  {nodes}"

    node_versions = {node["version"] for node in pools["nodes"]}
    expected = 2 if mixed else 1
    assert len(node_versions) == expected, \
        f"expected {expected} node version(s), got " \
        f"{sorted(node_versions)}:\n  {nodes}"
    return compat_mode_of(cluster)


def wait_for_compat_bump(cluster, previous, timeout_s=120):
    """Wait until the cluster's compat mode has moved off `previous`.

    Not something to assert the moment an upgrade step returns: the compat
    mode is raised after it. The orchestrator reports a rebalance finished
    before it considers switching, and once every node is on the new release
    it is the janitor's work rather than part of the upgrade itself.
    """
    reached = []

    def bumped():
        current = compat_mode_of(cluster)
        reached.append(current)
        return current != previous

    testlib.poll_for_condition(
        bumped, sleep_time=1, timeout=timeout_s,
        msg=f"waiting for compat mode to move off {previous}")
    return reached[-1]


class UpgradeContext:
    """The cluster, as the strategy and the suites see it.

    old_nodes is the cluster as it stood when the cycle started. new_nodes is
    empty until a transition brings replacements up through start_new_nodes(),
    so a suite that asks for a new node before one exists gets a clear failure
    rather than a stale answer.
    """

    def __init__(self, cluster, bucket_name):
        self.cluster = cluster
        self.bucket_name = bucket_name
        self.old_nodes = list(cluster.connected_nodes)
        self.new_nodes = []
        self.prior_compat_mode = None

    @property
    def compat_mode(self):
        return compat_mode_of(self.cluster)

    def verify(self, mixed):
        return verify_cluster(self.cluster, mixed)

    def nodes_upgraded(self, nodes):
        """Record that `nodes` now run the version under test.

        An in-place upgrade has no separate replacement node to point at --
        the nodes it upgraded are the nodes it started with -- so this is
        how they come to answer new_nodes for the suites.
        """
        for node in nodes:
            if node not in self.new_nodes:
                self.new_nodes.append(node)

    def wait_for_compat_bump(self):
        """Wait for the compat mode to leave the version we upgraded from.

        Then resample the cluster's capability flags: they follow the compat
        mode, not the binaries, so they go stale only once it has moved.
        """
        compat_mode = wait_for_compat_bump(self.cluster,
                                           self.prior_compat_mode)
        self.cluster.refresh_version_flags()
        return compat_mode

    def start_new_nodes(self, count):
        """Bring up `count` nodes on the version under test, unjoined.

        Returns the ones just started, and records them, so a strategy that
        replaces nodes a few at a time can call this more than once.
        """
        started = self.cluster.start_new_version_nodes(count)
        self.new_nodes += started
        return started


class UpgradeStrategy(ABC):
    """One kind of upgrade. Subclass this in a module under strategies/.

    Defining the subclass is what registers it -- see strategies/__init__.py.

    One instance is shared by every cycle this strategy runs, across every
    source version, so keep no per-run state on self: a transition is handed
    the UpgradeContext and everything it learns belongs there.
    """

    # How this strategy is named on the command line and in test output.
    name = None

    # The interface a suite inherits to declare it wants to be run by this
    # strategy. The callbacks this strategy's stages name are declared on it,
    # abstract, so inheriting it is both the declaration and the contract.
    # Two strategies that should always travel together can share one.
    suite_base = None

    # How many nodes the cluster starts with, and how many replacements the
    # cycle brings up. This is part of the strategy rather than a parameter of
    # one: an online 2-to-2 and an online 3-to-3 differ in the callbacks they
    # can offer a suite, so they are two strategies.
    old_node_count = None
    new_node_count = None

    def cluster_requirements(self):
        """What the cluster must look like before the cycle starts.

        Passed alongside the requirements the engine asks for, so a strategy
        names only the cluster's shape and none of the engine's own keys.
        Exactly old_node_count nodes: the transitions assume every connected
        node is one they replace.
        """
        return {'num_nodes': self.old_node_count}

    @abstractmethod
    def stages(self):
        """The cycle, in order, as callback() and transition() stages."""

    def callback_names(self):
        """The hooks this strategy invokes, in the order it invokes them."""
        return [stage.name for stage in self.stages()
                if stage.kind == CALLBACK]

    def __str__(self):
        return self.name
