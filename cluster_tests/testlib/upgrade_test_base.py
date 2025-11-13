# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""
Base class for individual upgrade check suites.

Instances are created and driven by UpgradeChecks in testsets/upgrade_tests.py.
Each subclass implements three hook methods called at different phases of a
single shared upgrade cycle:

    before_upgrade()       – old-version-only cluster
    mixed_cluster_checks() – both old and new nodes active
    post_upgrade_checks()  – new-version-only cluster

The following attributes are set on each instance before each phase call:

    self.cluster            — the cluster object
    self.old_node           — representative old-version node
    self.new_node           — representative new-version node
    self.old_nodes          — all old-version nodes
    self.new_nodes          — all new-version nodes
    self.compat_mode        — compat mode string (updated after upgrade)
    self.prior_compat_mode  — compat mode before upgrade (set in phase 5)
    self.bucket_name        — name of the pre-created test bucket

Typical usage:

    class MyFeatureChecks(UpgradeChecks):

        def before_upgrade(self):
            self.old_state = testlib.get_succ(self.old_node, "/...").json()

        def mixed_cluster_checks(self):
            # check behaviour visible from both self.old_node and self.new_node
            pass

        def post_upgrade_checks(self):
            new_state = testlib.get_succ(self.new_node, "/...").json()
            assert new_state == self.old_state
"""


class UpgradeChecks:

    # -------------------------------------------------------------------------
    # Hook methods — override in derived classes
    # -------------------------------------------------------------------------

    def before_upgrade(self):
        """Phase 1: only old-version nodes are in the cluster."""

    def mixed_cluster_checks(self):
        """Phase 3: both old and new nodes are active cluster members."""

    def post_upgrade_checks(self):
        """Phase 5: only new-version nodes remain.

        self.prior_compat_mode holds the compat mode that was in effect
        during phases 1-3, which is useful for distinguishing upgrade paths
        (e.g. '7.6' → new vs '8.0' → new).
        """

    # -------------------------------------------------------------------------
    # Helpers available to derived classes
    # -------------------------------------------------------------------------

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
        """Return the symmetric difference of a named field across two object lists."""
        old_set = {item[key] for item in old_list}
        new_set = {item[key] for item in new_list}
        return list(old_set.symmetric_difference(new_set))

    def diff_values_for_key(self, key, old_dict, new_dict):
        """Return the symmetric difference of the list stored at key in two dicts."""
        return list(set(old_dict.get(key, [])) ^ set(new_dict.get(key, [])))
