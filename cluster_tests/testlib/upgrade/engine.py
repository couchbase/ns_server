# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Runs one upgrade cycle and reports each suite's each hook separately.

The cycle itself is still fixed here -- start the replacement nodes, rebalance
them in, rebalance the old ones out. What changes is that the checks are no
longer a list this module holds: suites are discovered, and each hook of each
suite becomes an ordinary generated test. So one suite failing no longer leaves
every other suite without a verdict, and the report names the suite and the
hook rather than just the driver.
"""

import collections
import inspect
import os
import sys

import testlib
from testlib.requirements import UpgradeSpec
from testlib.upgrade import versions
from testlib.upgrade.suite import UpgradeCheckSuite

BUCKET_NAME = 'upgradeTestBucket'

# Where the generated testset is installed. Must be a module living in
# cluster_tests/testsets, since that is what discover_testsets() looks at.
HOST_MODULE = 'testsets.upgrade_tests'

# Also selects every generated testset in --tests; see run.py.
TESTSET_PREFIX = 'UpgradeChecks'

Stage = collections.namedtuple('Stage', ['kind', 'name', 'fn'])

CALLBACK = 'callback'
TRANSITION = 'transition'


def discover_suites():
    """Every UpgradeCheckSuite subclass defined in a module under testsets/.

    A leading underscore marks shared machinery -- the part of a suite that
    does not depend on the source version -- rather than a suite to run. A
    suite built on one must set from_version and whatever the shared base
    leaves as None; checked here rather than partway through a cycle.

    Walks sys.modules rather than importing the directory: importing it would
    pull in modules run.py deliberately leaves out, and discover_testsets()
    would then start running them.
    """
    testsets_dir = os.path.normpath(
        os.path.join(testlib.get_cluster_test_dir(), "testsets"))
    found = {}
    for module in list(sys.modules.values()):
        path = getattr(module, '__file__', None)
        if path is None or \
                os.path.normpath(os.path.dirname(path)) != testsets_dir:
            continue
        for name, cls in inspect.getmembers(module, inspect.isclass):
            if not issubclass(cls, UpgradeCheckSuite) or \
                    cls is UpgradeCheckSuite:
                continue
            if cls.__module__ != module.__name__:
                continue        # a re-export, not a definition
            if name.startswith('_'):
                continue        # shared machinery, not a suite
            unset = _unset_by_version(cls)
            assert not unset, \
                f"{name} does not set {', '.join(unset)}, which its shared " \
                f"base leaves to each source version"
            found[(cls.__module__, name)] = cls
    return [found[key] for key in sorted(found)]


def _unset_by_version(cls):
    shared = [base for base in cls.__mro__[1:]
              if issubclass(base, UpgradeCheckSuite) and
              base.__name__.startswith('_')]
    if not shared:
        return []
    names = {'from_version'}
    for base in shared:
        names |= {n for n, v in vars(base).items() if v is None}
    return sorted(n for n in names if getattr(cls, n) is None)


def conflicts(a, b):
    """Whether two suites would tread on each other sharing a cluster.

    Ordinary reader/writer rules over the tags: two readers of the same thing
    are fine, a writer and anyone else are not. A suite marked exclusive
    conflicts with everything.
    """
    if a.exclusive or b.exclusive:
        return True
    return bool((a.writes & b.writes) or (a.writes & b.reads) or
                (a.reads & b.writes))


def partition(suites):
    """Split suites into groups that can each share one cluster.

    Greedy first fit over suites in discovery order. Neither minimal nor
    stable: a new suite can move others to another group, so a group index
    means nothing across runs -- the testset's docstring lists its suites.
    """
    groups = []
    for suite in suites:
        for group in groups:
            if all(not conflicts(suite, other) for other in group):
                group.append(suite)
                break
        else:
            groups.append([suite])
    return groups


def plan(source_versions=None, suites=None):
    """[(from_version, group_index, [suite classes])] for the whole run.

    A suite applies to a source version if it names that one, or names none
    at all -- in which case it has to cope with whichever it is given.
    """
    source_versions = source_versions or versions.source_versions()
    suites = discover_suites() if suites is None else suites

    planned = []
    for from_version in source_versions:
        applicable = [s for s in suites
                      if s.from_version in (None, from_version)]
        for group_index, group in enumerate(partition(applicable)):
            planned.append((from_version, group_index, group))
    return planned


def cluster_compat_mode(cluster):
    """The cluster's compat mode as a string, e.g. '8.0'."""
    pools = testlib.get_succ(cluster, "/pools/default").json()
    modes = set()
    for node in pools["nodes"]:
        compat = node["clusterCompatibility"]
        modes.add(f"{compat >> 16}.{compat & 0xFFFF}")
    assert len(modes) == 1, f"expected a single compat mode, got {modes}"
    return modes.pop()


def verify_cluster(cluster, mixed):
    """Assert the cluster is healthy and return its compat mode.

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
    return cluster_compat_mode(cluster)


class UpgradeContext:
    """What the suites are given.

    old_nodes are the cluster as it stands when the cycle starts. new_nodes is
    empty until a transition starts replacement nodes and records them here,
    so a suite asking for a new node before one exists gets a clear failure
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
        return cluster_compat_mode(self.cluster)


class UpgradeTestSetBase(testlib.BaseTestSet):
    """Drives the cycle. Subclassed per generated testset."""

    _suite_classes = ()

    @staticmethod
    def requirements():
        raise NotImplementedError("set by _make_testset")

    _from_version = None

    def setup(self):
        self.ctx = UpgradeContext(self.cluster, BUCKET_NAME)
        self.ctx.prior_compat_mode = verify_cluster(self.cluster, mixed=False)
        # A cross-check: Upgrade.is_met has already refused any other cluster.
        assert self.ctx.prior_compat_mode == self._from_version, \
            f"cluster is at compat {self.ctx.prior_compat_mode}, expected " \
            f"{self._from_version}"
        self.suites = [cls(self.ctx) for cls in self._suite_classes]
        # A suite that failed one hook is skipped in its later ones: whatever
        # it meant to capture is not there.
        self._failed_suites = set()
        # Set by a transition that fails, so the rest of the cycle is skipped
        # rather than reported as a pile of unrelated failures.
        self._cycle_aborted = None
        print(f"upgrade from {self.ctx.prior_compat_mode}: "
              f"{', '.join(str(s) for s in self.suites)}")

    def test_teardown(self):
        # Runs after every unit, so it must stay a no-op: a failure here would
        # mark all the remaining units of the cycle as not run.
        pass

    def teardown(self):
        # is_met() assumes a cluster still satisfies its requirements once a
        # testset has finished, so that the cluster can be reused by a later
        # testset. The cycle leaves the cluster in a state that no longer
        # satisfies the upgrade requirement (whether or not it ran to
        # completion), so mark it as spent here rather than only on the success
        # path, ensuring it isn't handed to another testset expecting a fresh
        # mixed-version cluster. Note new_version_nodes is deliberately left
        # populated: that is now what marks the cluster as already upgraded.
        self.cluster.set_requirements(None)

        # Every suite's cleanup, whatever happened to its hooks: a suite that
        # failed may well have created something before it did. Here rather
        # than as units of the cycle, since the harness can skip those but
        # always runs teardown. Nothing reuses an upgrade cluster yet; this
        # keeps it tidy for when something does.
        errors = []
        for suite in self.suites:
            try:
                suite.cleanup()
            except Exception as e:
                errors.append(str(e))
        assert not errors, "\n".join(errors)

    # -- the cycle --------------------------------------------------------

    def _stages(self):
        return [Stage(CALLBACK, 'before_upgrade', None),
                Stage(TRANSITION, 'add-new-nodes-and-rebalance-in',
                      self._rebalance_in),
                Stage(CALLBACK, 'mixed_cluster_checks', None),
                Stage(TRANSITION, 'rebalance-out-old-nodes',
                      self._rebalance_out),
                Stage(CALLBACK, 'post_upgrade_checks', None)]

    def _rebalance_in(self):
        # The replacement nodes are started here, not when the cluster was
        # built: it is this cycle that knows how many it needs and when.
        self.ctx.new_nodes = self.cluster.start_new_version_nodes(
            len(self.ctx.old_nodes))
        # Join each new-version node with the same services as its
        # corresponding old-version node, rather than relying on add_node's
        # default (which would pick up the services of whichever connected
        # node happens to handle the addNode request).
        for old_node, new_node in zip(self.ctx.old_nodes, self.ctx.new_nodes):
            self.cluster.add_node(new_node, services=old_node.get_services())
        self.cluster.rebalance(wait=True)
        verify_cluster(self.cluster, mixed=True)

    def _rebalance_out(self):
        self.cluster.rebalance(ejected_nodes=list(self.ctx.old_nodes),
                               wait=True, verbose=True,
                               node=self.ctx.new_nodes[0])
        # The cluster's cached capability flags described the release it came
        # from; they have to be resampled now it is on another one. Before the
        # checks, so a failed one does not leave them stale for the next reuse
        # check.
        self.cluster.refresh_version_flags()
        compat_mode = verify_cluster(self.cluster, mixed=False)
        assert self.ctx.prior_compat_mode != compat_mode, \
            f"Compat mode did not change after upgrade " \
            f"(still {compat_mode!r})"

    # -- the cycle, as generated tests ------------------------------------

    def upgrade_test_gen(self):
        """Build the units. Pure: this is itself a reported, timed test, so it
        must not touch the cluster."""
        units = {}

        def add(name, fn):
            # The units are a dict, so a repeated name would drop a unit
            # rather than fail.
            assert name not in units, f"duplicate unit name {name!r}"
            units[name] = fn

        for stage in self._stages():
            if stage.kind == TRANSITION:
                add(f"transition:{stage.name}",
                    self._transition_unit(stage))
            else:
                for suite in self.suites:
                    add(f"{suite}:{stage.name}",
                        self._callback_unit(suite, stage.name))
        return units

    def _callback_unit(self, suite, callback):
        def run(_self):
            if self._cycle_aborted:
                raise testlib.TestNotRun(
                    f"cycle aborted at {self._cycle_aborted}")
            if str(suite) in self._failed_suites:
                raise testlib.TestNotRun(
                    "suite failed an earlier callback, so its state is "
                    "untrustworthy")
            try:
                getattr(suite, callback)()
            except Exception:
                self._failed_suites.add(str(suite))
                raise
        return run

    def _transition_unit(self, stage):
        def run(_self):
            if self._cycle_aborted:
                raise testlib.TestNotRun(
                    f"cycle aborted at {self._cycle_aborted}")
            try:
                stage.fn()
            except Exception as e:
                self._cycle_aborted = f"{stage.name} ({e!r})"
                raise
        return run


def testset_name(from_version, group_index):
    return (f"{TESTSET_PREFIX}_from{from_version.replace('.', '')}"
            f"_g{group_index}")


def _make_testset(from_version, group_index, suite_classes):
    spec = UpgradeSpec(from_version, group_index)

    def requirements(_spec=spec):
        return testlib.ClusterRequirements(
            min_num_nodes=2,
            balanced=True,
            num_vbuckets=16,
            # Routes cluster.build_cluster through legacy_cluster so the
            # cluster starts on that release's binaries, from the checkout
            # given for it with --upgrade-from. Distinct specs are distinct
            # requirements, which is what gives each cycle its own cluster.
            upgrade=_spec,
            buckets=[{"name": BUCKET_NAME,
                      "storageBackend": "couchstore",
                      "replicaNumber": 1,
                      "ramQuota": 100}])

    name = testset_name(from_version, group_index)
    return name, type(name, (UpgradeTestSetBase,), {
        '_suite_classes': tuple(suite_classes),
        '_from_version': from_version,
        '__module__': HOST_MODULE,
        '__doc__': f"Upgrade checks from {from_version}: "
                   + ', '.join(c.__name__ for c in suite_classes),
        'requirements': staticmethod(requirements),
    })


def install_testsets(verbose=True):
    """Generate the upgrade testsets and install them for discovery.

    One per (source version, group of suites that can share a cluster). Must
    run after the suites' modules are imported and before discover_testsets().
    Returns the names installed.
    """
    planned = plan()
    if not planned:
        return []

    host = sys.modules.get(HOST_MODULE)
    assert host is not None, \
        f"{HOST_MODULE} must be imported before installing upgrade testsets"

    names = []
    for from_version, group_index, group in planned:
        name, cls = _make_testset(from_version, group_index, group)
        setattr(host, name, cls)
        names.append(name)
        if verbose:
            print(f"  {name}: " + ', '.join(c.__name__ for c in group))
    return names
