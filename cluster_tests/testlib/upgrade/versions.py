# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Source-version registry for upgrade testing.

Maps each source version to the checkout providing its binaries, and loads that
checkout's pylib/cluster_run_lib.py on demand.

Loading the module is what selects which binaries a node runs: each copy
derives its own PREFIX and APPROOT from its own
build/cluster_run.configuration, while root_dir and start_index -- which come
from the harness -- pin the node's data directory, log directory and couch
ini.
"""

import importlib.util
import os

import testlib

# Source versions we know how to upgrade from. A version belongs here once
# ns_config_default:upgrade_config/1 has a rung for its config_version.
SUPPORTED_SOURCE_VERSIONS = ('7.6', '8.0')

# version -> module, so each checkout's file is executed once.
_lib_cache = {}


def cluster_run_lib_path(checkout_path):
    return os.path.join(checkout_path, 'pylib', 'cluster_run_lib.py')


def upgrade_paths():
    """{source version: checkout path} for the versions this run tests."""
    return testlib.config.get('upgrade_paths', {})


def source_versions():
    return tuple(sorted(upgrade_paths(),
                        key=lambda v: tuple(map(int, v.split('.')))))


def parse_upgrade_from(arg, into=None):
    """Parse '<version>=<path>' into a {version: path} dict.

    Raises ValueError with a message meant for the user.
    """
    paths = dict(into or {})
    version, sep, path = arg.partition('=')
    version, path = version.strip(), path.strip()
    if not sep or not version or not path:
        raise ValueError(
            f"'{arg}' is not <version>=<path>, e.g. "
            f"8.0=/src/morpheus/ns_server")
    if version not in SUPPORTED_SOURCE_VERSIONS:
        raise ValueError(
            f"unsupported source version '{version}'; must be one of: "
            f"{', '.join(SUPPORTED_SOURCE_VERSIONS)}")
    # The shell leaves a ~ after '=' alone, and a relative path would depend
    # on where run.py was started.
    path = os.path.abspath(os.path.expanduser(path))
    lib = cluster_run_lib_path(path)
    if not os.path.exists(lib):
        raise ValueError(f"cannot access '{lib}' for version {version}")
    if version in paths and paths[version] != path:
        raise ValueError(
            f"version {version} given twice, with different paths: "
            f"'{paths[version]}' and '{path}'")
    paths[version] = path
    return paths


def get_cluster_run_lib(version):
    """The cluster_run_lib module whose binaries `version` should run."""
    if version in _lib_cache:
        return _lib_cache[version]

    path = upgrade_paths().get(version)
    if path is None:
        raise RuntimeError(
            f"no checkout registered for source version {version}; pass "
            f"--upgrade-from {version}=<path>")

    lib_path = cluster_run_lib_path(path)
    if not os.path.exists(lib_path):
        raise RuntimeError(f"{lib_path} not found")

    module_name = f"cluster_run_lib_{version.replace('.', '_')}"
    spec = importlib.util.spec_from_file_location(module_name, lib_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _lib_cache[version] = module
    return module
