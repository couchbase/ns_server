# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Plans the upgrade runs and reports each suite's each hook separately.

This module knows that an upgrade is a sequence of stages, that a transition
moves the cluster and a callback asks the suites about it, and that each of
those is worth reporting on its own. It does not know what any particular
upgrade does: the stages come from a strategy, and strategies live in
strategies/ where adding one needs no change here.

What it does own is the planning. One cluster per (strategy, source version,
group of suites that can share one), each generated as its own testset, so
the harness builds one cluster for each and runs the cycle on it.
"""

import inspect
import os
import re
import sys

import testlib
from testlib.requirements import UpgradeSpec
from testlib.upgrade import strategies, versions
from testlib.upgrade.strategy import CALLBACK, TRANSITION, UpgradeContext
from testlib.upgrade.suite import UpgradeCheckSuite

BUCKET_NAME = 'upgradeTestBucket'

# Where the generated testset is installed. Must be a module living in
# cluster_tests/testsets, since that is what discover_testsets() looks at.
HOST_MODULE = 'testsets.upgrade_tests'

# Also selects every generated testset in --tests; see run.py.
TESTSET_PREFIX = 'UpgradeChecks'


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
            if unset:
                raise ValueError(
                    f"{name} does not set {', '.join(unset)}, which its "
                    f"shared base leaves to each source version")
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


def suites_for(strategy, suites):
    """The suites that opted into `strategy`, checked against its contract.

    A suite opts in by inheriting the strategy's suite_base, so issubclass is
    the whole of the question "does this suite run under this strategy".

    The callbacks are abstract on that interface, so Python would refuse to
    instantiate a suite that missed one -- but only once the cycle was
    already running. Checking here instead names the suite and what it
    misses before any cluster is built. Raises ValueError, which run.py
    reports as a usage error.
    """
    if strategy.suite_base is None:
        raise ValueError(f"strategy {strategy} declares no suite_base, so no "
                         f"suite can opt into it")

    undeclared = [name for name in strategy.callback_names()
                  if not hasattr(strategy.suite_base, name)]
    if undeclared:
        raise ValueError(
            f"strategy {strategy} invokes {', '.join(undeclared)}, which "
            f"{strategy.suite_base.__name__} does not declare, so no suite "
            f"can know to implement it")

    selected = []
    for suite in suites:
        if not issubclass(suite, strategy.suite_base):
            continue
        # Computed by Python when the class is defined, so it covers every
        # interface the suite inherits, not just this strategy's callbacks.
        missing = sorted(getattr(suite, '__abstractmethods__', ()))
        if missing:
            raise ValueError(f"{suite.__name__} does not implement "
                             f"{', '.join(missing)}")
        selected.append(suite)
    return selected


def unclaimed_suites(strategies_=None, suites=None):
    """Suites no strategy will ever run, because they opted into none.

    A suite is only ever reached through a strategy's interface, so one that
    inherits none is dead code. Easy to write by accident, and silent without
    this. Asked of every strategy, not only the selected ones: a suite
    written for a strategy this run leaves out is not an orphan.
    """
    strategies_ = strategies.all_strategies() if strategies_ is None \
        else strategies_
    suites = discover_suites() if suites is None else suites
    bases = tuple(s.suite_base for s in strategies_ if s.suite_base)
    return [s for s in suites if not issubclass(s, bases)]


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


def plan(strategies_=None, source_versions=None, suites=None):
    """[(strategy, from_version, group_index, [suite classes])] for the run.

    Every combination of a strategy and a source version is a separate
    upgrade, and each group within one needs its own cluster. A suite is run
    by a strategy if it inherits that strategy's interface, and applies to a
    source version if it names that one or names none at all -- in which case
    it has to cope with whichever it is given.
    """
    strategies_ = strategies.selected() if strategies_ is None else strategies_
    source_versions = source_versions or versions.source_versions()
    suites = discover_suites() if suites is None else suites

    planned = []
    for strategy in strategies_:
        eligible = suites_for(strategy, suites)
        for from_version in source_versions:
            applicable = [s for s in eligible
                          if s.from_version in (None, from_version)]
            for group_index, group in enumerate(partition(applicable)):
                planned.append((strategy, from_version, group_index, group))
    return planned


class UpgradeTestSetBase(testlib.BaseTestSet):
    """Runs one strategy's cycle. Subclassed per generated testset."""

    _suite_classes = ()

    @staticmethod
    def requirements():
        raise NotImplementedError("set by _make_testset")

    _from_version = None
    _strategy = None

    def setup(self):
        self.ctx = UpgradeContext(self.cluster, BUCKET_NAME)
        self.ctx.prior_compat_mode = self.ctx.verify(mixed=False)
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
        print(f"{self._strategy} upgrade from "
              f"{self.ctx.prior_compat_mode}: "
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

        for stage in self._strategy.stages():
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
                stage.fn(self.ctx)
            except Exception as e:
                self._cycle_aborted = f"{stage.name} ({e!r})"
                raise
        return run


def testset_name(strategy, from_version, group_index):
    # A testset name is a class name, so anything a strategy might have in
    # its own name -- 'online-2to2' -- has to come out.
    strategy_part = re.sub(r'[^0-9a-zA-Z]', '', str(strategy))
    return (f"{TESTSET_PREFIX}_{strategy_part}"
            f"_from{from_version.replace('.', '')}"
            f"_g{group_index}")


def _make_testset(strategy, from_version, group_index, suite_classes):
    spec = UpgradeSpec(str(strategy), from_version, group_index)
    # The strategy says what shape of cluster its upgrade needs; everything
    # else about the cluster is the same whichever upgrade is being tested.
    shape = strategy.cluster_requirements()

    def requirements(_spec=spec, _shape=shape):
        return testlib.ClusterRequirements(
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
                      "ramQuota": 100}],
            **_shape)

    name = testset_name(strategy, from_version, group_index)
    return name, type(name, (UpgradeTestSetBase,), {
        '_suite_classes': tuple(suite_classes),
        '_from_version': from_version,
        '_strategy': strategy,
        '__module__': HOST_MODULE,
        '__doc__': f"{strategy} upgrade from {from_version}: "
                   + ', '.join(c.__name__ for c in suite_classes),
        'requirements': staticmethod(requirements),
    })


def install_testsets(verbose=True):
    """Generate the upgrade testsets and install them for discovery.

    One per (strategy, source version, group of suites that can share a
    cluster). Must run after the suites' modules are imported and before
    discover_testsets(). Returns the names installed.
    """
    orphans = unclaimed_suites()
    if orphans and verbose:
        print(testlib.yellow(
            "  WARNING: no strategy runs " +
            ", ".join(s.__name__ for s in orphans) +
            " -- a suite is run only by the strategies whose interface it "
            "inherits"))

    planned = plan()
    if not planned:
        return []

    host = sys.modules.get(HOST_MODULE)
    assert host is not None, \
        f"{HOST_MODULE} must be imported before installing upgrade testsets"

    names = []
    for strategy, from_version, group_index, group in planned:
        name, cls = _make_testset(strategy, from_version, group_index, group)
        # Two strategy names can differ only in what testset_name() strips.
        if name in names:
            raise ValueError(f"two upgrade testsets are named {name}")
        setattr(host, name, cls)
        names.append(name)
        if verbose:
            print(f"  {name}: " + ', '.join(c.__name__ for c in group))
    return names
