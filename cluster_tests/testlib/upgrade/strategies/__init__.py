# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""The upgrade strategies, discovered rather than listed.

Adding a kind of upgrade is adding a module to this package: every module
here is imported on first use, and any UpgradeStrategy subclass it defines is
registered under its own name. Nothing outside this package names a strategy,
so the engine never has to be told about one.
"""

import importlib
import inspect
import os
import pkgutil

import testlib
from testlib.upgrade.strategy import UpgradeStrategy

_registry = None


def _discover():
    """{name: class} for every strategy defined in this package."""
    found = {}
    for module_info in pkgutil.iter_modules([os.path.dirname(__file__)]):
        module = importlib.import_module(f"{__name__}.{module_info.name}")
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if not issubclass(cls, UpgradeStrategy) or \
                    cls is UpgradeStrategy or inspect.isabstract(cls):
                continue
            if cls.__module__ != module.__name__:
                continue        # a re-export, not a definition
            assert cls.name, \
                f"{cls.__module__}.{cls.__name__} does not set a name"
            clash = found.get(cls.name)
            assert clash is None, \
                f"{cls.__name__} and {clash.__name__} are both called " \
                f"{cls.name!r}"
            found[cls.name] = cls
    return found


def _classes():
    global _registry
    if _registry is None:
        _registry = _discover()
    return _registry


def all_strategies():
    """One instance of every registered strategy, in a stable order.

    Stable so that the testsets a run generates, and the clusters it builds
    for them, do not reshuffle when a strategy is added.
    """
    registry = _classes()
    return [registry[name]() for name in sorted(registry)]


def get(name):
    """The strategy called `name`, or ValueError naming the ones there are."""
    registry = _classes()
    if name not in registry:
        raise ValueError(
            f"unknown upgrade strategy {name!r}; must be one of: "
            f"{', '.join(sorted(registry))}")
    return registry[name]()


def parse_strategies(arg):
    """Parse a comma-separated list of strategy names into instances.

    Raises ValueError with a message meant for the user.
    """
    selected = []
    for entry in arg.split(','):
        entry = entry.strip()
        if not entry:
            continue
        strategy = get(entry)
        if strategy.name not in [s.name for s in selected]:
            selected.append(strategy)
    if not selected:
        raise ValueError("no strategy named")
    return selected


def selected():
    """The strategies this run was asked for; all of them by default."""
    wanted = testlib.config.get('upgrade_strategies')
    return list(wanted) if wanted else all_strategies()
