# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Base class for upgrade check suites.

A suite is a set of checks for one feature area, run at each point of an
upgrade cycle. Subclass this, implement the hooks you need, and put the class
in any module under testsets/ -- preferably the one that already tests the
feature. Suites are discovered, not registered.

    before_upgrade()        only the old version is present
    mixed_cluster_checks()  both versions are active
    post_upgrade_checks()   only the new version remains
    cleanup()               at the end of the cycle, however it ended

Suites share a cluster with the others they do not conflict with, so name
anything you create through name(), filter any cluster-wide listing through
owns(), and register the undo with delete_on_cleanup() or on_cleanup()
rather than undoing it at the end of a hook -- a hook that fails never
reaches its own last line.

Each hook is reported as its own test, so a suite that fails one hook is
skipped in its later ones while every other suite still reports its own
result.

The cluster is reached through the properties below rather than through
attributes the driver injects.
"""

import testlib


class UpgradeCheckSuite:

    # The release this suite upgrades from, e.g. '8.0'. None means it applies
    # to every source version the run was asked for, and so must cope with
    # each of them itself.
    from_version = None

    # What this suite touches, as opaque tags -- name the REST path by
    # convention ('settings/alerts', 'rbac/users'). The engine puts suites
    # that do not conflict on one cluster and one upgrade cycle, so declare
    # these finely: a suite reading 'rbac/roles' and one writing 'rbac/users'
    # can then share a cycle.
    reads = frozenset()
    writes = frozenset()

    # Set on a suite that perturbs the whole cluster -- rebalances, fails a
    # node over, restarts one. Such a suite gets a cluster to itself.
    exclusive = False

    def __init__(self, ctx):
        self._ctx = ctx
        self._cleanups = []

    def __str__(self):
        return type(self).__name__

    # -- the cluster, at this point in the cycle --------------------------

    @property
    def cluster(self):
        return self._ctx.cluster

    @property
    def bucket_name(self):
        """The bucket the engine created for the suites to share."""
        return self._ctx.bucket_name

    @property
    def old_nodes(self):
        return self._ctx.old_nodes

    @property
    def new_nodes(self):
        return self._ctx.new_nodes

    @property
    def old_node(self):
        return self._one(self.old_nodes, 'old')

    @property
    def new_node(self):
        return self._one(self.new_nodes, 'new')

    @property
    def compat_mode(self):
        """The cluster's compat mode right now.

        Still the old version for as long as any old node remains, so a mixed
        cluster reports the version being upgraded from.
        """
        return self._ctx.compat_mode

    @property
    def prior_compat_mode(self):
        """The compat mode the cluster had before the upgrade."""
        return self._ctx.prior_compat_mode

    def _one(self, nodes, which):
        assert nodes, f"[{self}] the cluster has no {which}-version node"
        return nodes[0]

    # -- naming what you create ------------------------------------------

    @property
    def prefix(self):
        """This suite's namespace.

        Suites share a cluster, so everything a suite creates must be named
        through name(), and any cluster-wide listing it asserts on must be
        filtered through owns(). Otherwise a suite sees, and may delete,
        another's data.
        """
        return f"ut_{type(self).__name__}_"

    def name(self, suffix):
        return f"{self.prefix}{suffix}"

    def owns(self, name):
        return name.startswith(self.prefix)

    # -- undoing what you created ----------------------------------------

    def on_cleanup(self, fn, description):
        """Register something to undo at the end of the cycle."""
        self._cleanups.append((fn, description))

    def delete_on_cleanup(self, path):
        """Register a DELETE for the end of the cycle.

        Sent through the cluster, which picks a node that is still in it when
        cleanup runs: the node this was created through may have left by then.
        """
        self.on_cleanup(lambda: testlib.ensure_deleted(self.cluster, path),
                        f"DELETE {path}")

    # -- hooks: override the ones your checks need -----------------------

    def before_upgrade(self):
        """Only the old version is present. Capture what you will compare."""

    def mixed_cluster_checks(self):
        """Both versions are active."""

    def post_upgrade_checks(self):
        """Only the new version remains."""

    def cleanup(self):
        """Runs from the testset's teardown, so even after a hook failed or
        was skipped.

        The default drains the registry in reverse, attempting every entry
        even if an earlier one fails, so one stuck deletion cannot leak the
        rest. Override only for something the registry cannot express.
        """
        errors = []
        for fn, description in reversed(self._cleanups):
            try:
                fn()
            except Exception as e:
                errors.append(f"{description}: {e}")
        assert not errors, \
            f"[{self}] cleanup failed:\n  " + "\n  ".join(errors)

    # -- helpers ---------------------------------------------------------

    def compare_json_keys(self, json1, json2, prefix="", check_values=False):
        """Compare keys between two JSON dicts; return list of mismatches.

        A mismatch is a key present in one dict but not the other, or —
        when check_values=True — a key whose values differ between the two.
        Recurses into nested dicts, using dotted key paths in the result.
        """
        mismatches = []
        if not isinstance(json1, dict) or not isinstance(json2, dict):
            return mismatches
        keys1 = set(json1.keys())
        keys2 = set(json2.keys())
        for key in sorted(keys1 - keys2):
            print(f"Key '{prefix + key}' missing in second JSON")
            mismatches.append(prefix + key)
        for key in sorted(keys2 - keys1):
            print(f"Key '{prefix + key}' missing in first JSON")
            mismatches.append(prefix + key)
        for key in sorted(keys1 & keys2):
            val1, val2 = json1[key], json2[key]
            if isinstance(val1, dict) and isinstance(val2, dict):
                mismatches.extend(
                    self.compare_json_keys(val1, val2, prefix + key + ".",
                                           check_values=check_values))
            elif check_values and val1 != val2:
                print(f"Key '{prefix + key}' values differ: "
                      f"{val1!r} vs {val2!r}")
                mismatches.append(f"{prefix + key}:value")
        return mismatches

    def diffs_for_key(self, key, old_list, new_list):
        """Symmetric difference of a named field across two object lists."""
        old_set = {item[key] for item in old_list}
        new_set = {item[key] for item in new_list}
        return list(old_set.symmetric_difference(new_set))

    def diff_values_for_key(self, key, old_dict, new_dict):
        """Symmetric difference of the list stored at key in two dicts."""
        return list(set(old_dict.get(key, [])) ^ set(new_dict.get(key, [])))
