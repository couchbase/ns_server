# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""
Example upgrade check suite — copy this file as a starting point.

Steps to add a new check suite:
  1. Create a new file in testsets/ (or add a class to an existing one).
  2. Subclass UpgradeChecks and implement the three hook methods below.
  3. Import the class in upgrade_tests.py and append it to
     UpgradeChecks._check_classes.

The following attributes are available on self inside every hook:

    self.cluster            — the cluster object
    self.old_node           — a representative old-version node
    self.new_node           — a representative new-version node
    self.old_nodes          — all old-version nodes
    self.new_nodes          — all new-version nodes
    self.compat_mode        — current compat-mode string, e.g. '8.0'
    self.prior_compat_mode  — compat mode before upgrade (phase 5 only)
    self.bucket_name        — name of the pre-created test bucket

Helper methods inherited from UpgradeChecks:

    compare_json_keys(j1, j2, check_values=False)
        Returns keys present in one dict but not the other.  Pass
        check_values=True to also flag keys whose values differ.

    diffs_for_key(key, old_list, new_list)
        Symmetric difference of a named field across two lists of objects.

    diff_values_for_key(key, old_dict, new_dict)
        Symmetric difference of the list stored at key in two dicts.
"""

import testlib
from testlib.upgrade_test_base import UpgradeChecks


class ExampleUpgradeChecks(UpgradeChecks):
    """Checks that /pools/default cluster name is preserved across upgrade."""

    # ------------------------------------------------------------------
    # Phase 1: old-version-only cluster
    # ------------------------------------------------------------------
    def before_upgrade(self):
        pools = testlib.get_succ(self.old_node, "/pools/default").json()
        self.old_cluster_name = pools["name"]

    # ------------------------------------------------------------------
    # Phase 3: mixed cluster (old and new nodes both active)
    # ------------------------------------------------------------------
    def mixed_cluster_checks(self):
        # Verify the cluster name is consistent across both versions.
        for node in [self.old_node, self.new_node]:
            pools = testlib.get_succ(node, "/pools/default").json()
            assert pools["name"] == self.old_cluster_name, \
                f"Cluster name mismatch on {node}: " \
                f"expected {self.old_cluster_name!r}, got {pools['name']!r}"

    # ------------------------------------------------------------------
    # Phase 5: new-version-only cluster
    # ------------------------------------------------------------------
    def post_upgrade_checks(self):
        pools = testlib.get_succ(self.new_node, "/pools/default").json()
        assert pools["name"] == self.old_cluster_name, \
            f"Cluster name changed after upgrade: " \
            f"expected {self.old_cluster_name!r}, got {pools['name']!r}"
