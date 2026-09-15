# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Upgrade check suites, grouped by feature area.

Each suite implements the hooks it needs and is discovered automatically -- see
testlib/upgrade/suite.py. A suite may live in any module under testsets/;
putting it beside the feature it covers is preferred.

This module is also where the generated upgrade testset is installed, which is
why run.py imports it even though it defines no BaseTestSet of its own.
"""

import testlib
from testlib.upgrade.suite import UpgradeCheckSuite
# Imported for its side effect: the engine discovers suites in any module
# under testsets/, and this one is not in run.py's import list.
from testsets import example_upgrade_checks  # noqa: F401
from testsets import jwt_upgrade_checks  # noqa: F401


class AlertsUpgradeChecks(UpgradeCheckSuite):

    def before_upgrade(self):
        self.old_alerts = testlib.get_succ(self.old_node,
                                            "/settings/alerts").json()

    def mixed_cluster_checks(self):
        new_alerts = testlib.get_succ(self.new_node, "/settings/alerts").json()
        assert self.compare_json_keys(self.old_alerts, new_alerts) == []
        if self.compat_mode != '7.6':
            # For a 7.6→8.x mixed cluster the 8.x node exposes its own alert
            # definitions (alerts added and removed relative to 7.6) regardless
            # of compat mode, so skip value comparison — post_upgrade_checks
            # verifies the exact delta after the upgrade completes.
            assert self.diff_values_for_key("alerts",
                                             self.old_alerts, new_alerts) == []
            assert self.diff_values_for_key("pop_up_alerts",
                                             self.old_alerts, new_alerts) == []

    def post_upgrade_checks(self):
        new_alerts = testlib.get_succ(self.new_node, "/settings/alerts").json()
        assert self.compare_json_keys(self.old_alerts, new_alerts) == []

        for field in ("alerts", "pop_up_alerts"):
            mismatches = self.diff_values_for_key(field, self.old_alerts,
                                                   new_alerts)
            if self.prior_compat_mode == '7.6':
                # Alerts added post-7.6 (in 8.0 or 8.5) plus alerts removed
                # in 8.0 (stuck_rebalance) and added in 8.0 (disk_guardrail).
                expected = [
                    'encr_at_rest_key_test_failed',
                    'encr_at_rest_errors_total',
                    'xdcr_replication_deleted',
                    'cm_bucket_autoreprovision_total',
                    'backup_failure',
                    'cont_backup_event_failed',
                    'cont_backup_gaps',
                    'disk_guardrail',
                    'stuck_rebalance',
                    'crl_expires_soon',
                    'crl_unusable']
                assert sorted(mismatches) == sorted(expected)
            elif self.prior_compat_mode == '8.0':
                expected = [
                    'encr_at_rest_key_test_failed',
                    'encr_at_rest_errors_total',
                    'xdcr_replication_deleted',
                    'cm_bucket_autoreprovision_total',
                    'backup_failure',
                    'cont_backup_event_failed',
                    'cont_backup_gaps',
                    'crl_expires_soon',
                    'crl_unusable']
                assert sorted(mismatches) == sorted(expected)
            else:
                raise AssertionError(
                    f"Unexpected prior_compat_mode: "
                    f"{self.prior_compat_mode!r}")


class BucketSettingsUpgradeChecks(UpgradeCheckSuite):

    def before_upgrade(self):
        path = f"/pools/default/buckets/{self.bucket_name}"
        self.old_bucket_info = testlib.get_succ(self.old_node, path).json()

    def mixed_cluster_checks(self):
        path = f"/pools/default/buckets/{self.bucket_name}"
        new_bucket_info = testlib.get_succ(self.new_node, path).json()
        mismatches = self.compare_json_keys(self.old_bucket_info, new_bucket_info)
        if self.compat_mode == '7.6':
            expected = ['pitrEnabled', 'pitrGranularity', 'pitrMaxHistoryAge']
        else:
            expected = []
        assert sorted(mismatches) == sorted(expected)

        # Memcached buckets must be rejected by both versions.
        data = {"name": "memcachedBucket",
                "bucketType": "memcached",
                "ramQuota": 100}
        expected_err = {"bucketType":
                        "memcached buckets are no longer supported"}

        r = testlib.post_fail(self.old_node, "/pools/default/buckets",
                              expected_code=400, data=data).json()
        if self.compat_mode == '7.6':
            assert r == {'_': 'memcached buckets are no longer supported'}
        elif self.compat_mode == '8.0':
            assert r['errors'] == expected_err

        r = testlib.post_fail(self.new_node, "/pools/default/buckets",
                              expected_code=400, data=data).json()
        assert r['errors'] == expected_err

    def post_upgrade_checks(self):
        path = f"/pools/default/buckets/{self.bucket_name}"
        new_bucket_info = testlib.get_succ(self.new_node, path).json()
        mismatches = self.compare_json_keys(self.old_bucket_info, new_bucket_info)
        if self.prior_compat_mode == '7.6':
            expected = [
                    # Removed post 7.6
                    'pitrEnabled', 'pitrGranularity', 'pitrMaxHistoryAge',
                    # Added in 8.0
                    'accessScannerEnabled',
                    'dcpBackfillIdleDiskThreshold',
                    'dcpBackfillIdleLimitSeconds',
                    'dcpBackfillIdleProtectionEnabled',
                    'dcpConnectionsBetweenNodes',
                    'durabilityImpossibleFallback',
                    'encryptionAtRestDekLifetime',
                    'encryptionAtRestDekRotationInterval',
                    'encryptionAtRestInfo',
                    'encryptionAtRestKeyId', 'expiryPagerSleepTime',
                    'hlcMaxFutureThreshold', 'invalidHlcStrategy',
                    'memoryHighWatermark', 'memoryLowWatermark',
                    'warmupBehavior',
                    # Added in 8.5
                    'dataServiceRebalanceType',
                    'continuousBackupCloudStorageCredId',
                    'continuousBackupKmCredId', 'continuousBackupKmKeyUrl',
                    'continuousBackupLocation', 'continuousBackupInterval',
                    'continuousBackupRetentionPeriod',
                    'chronicleRev',
                    'externalCollectionsManifestUid', 'throttleHardLimit',
                    'throttleReserved']
        elif self.prior_compat_mode == '8.0':
            expected = [
                    'chronicleRev', 'dataServiceRebalanceType',
                    'continuousBackupCloudStorageCredId',
                    'continuousBackupKmCredId', 'continuousBackupKmKeyUrl',
                    'continuousBackupLocation', 'continuousBackupInterval',
                    'continuousBackupRetentionPeriod',
                    'externalCollectionsManifestUid', 'throttleHardLimit',
                    'throttleReserved']
        else:
            raise AssertionError(
                f"Unexpected prior_compat_mode: {self.prior_compat_mode!r}")
        assert sorted(mismatches) == sorted(expected)


class RbacRolesUpgradeChecks(UpgradeCheckSuite):

    def before_upgrade(self):
        self.old_roles = testlib.get_succ(self.old_node,
                                           "/settings/rbac/roles").json()

    def mixed_cluster_checks(self):
        # Both nodes in the cluster must expose the same set of role names.
        new_roles = testlib.get_succ(self.new_node,
                                      "/settings/rbac/roles").json()
        assert self.diffs_for_key("role", self.old_roles, new_roles) == []

    def post_upgrade_checks(self):
        new_roles = testlib.get_succ(self.new_node,
                                      "/settings/rbac/roles").json()
        mismatches = self.diffs_for_key("role", self.old_roles, new_roles)
        if self.prior_compat_mode == '7.6':
            expected = [
                'user_admin_external', 'ro_security_admin',
                'credential_admin',
                'application_telemetry_writer', 'query_manage_system_catalog',
                'ui_access', 'security_admin', 'query_list_index',
                'user_admin_local', 'security_admin_local',
                'security_admin_external', 'credential_consumer',
                'external_catalog_admin', 'external_catalog_reader']
        elif self.prior_compat_mode == '8.0':
            expected = ['ui_access', 'credential_consumer', 'credential_admin',
                        'external_catalog_admin', 'external_catalog_reader']
        else:
            raise AssertionError(
                f"Unexpected prior_compat_mode: {self.prior_compat_mode!r}")
        assert sorted(mismatches) == sorted(expected)


class RbacRoleChangesUpgradeChecks(UpgradeCheckSuite):

    def before_upgrade(self):
        pass

    def mixed_cluster_checks(self):
        # Users created on one version must be visible with identical roles
        # on the other version.
        def put_user(username, roles):
            for node, suffix in [(self.old_node, 'old'), (self.new_node, 'new')]:
                testlib.put_succ(
                    node,
                    f"/settings/rbac/users/local/{username}-{suffix}",
                    data={'roles': roles, 'password': testlib.random_str(8)})

        def verify_cross_node_roles(username):
            on_old = testlib.get_succ(
                self.old_node,
                f"/settings/rbac/users/local/{username}-new").json()
            on_new = testlib.get_succ(
                self.new_node,
                f"/settings/rbac/users/local/{username}-old").json()
            assert (sorted(r['role'] for r in on_old['roles']) ==
                    sorted(r['role'] for r in on_new['roles']))

        put_user('couchbaseAdmin', 'admin')
        put_user('roadmin', 'ro_admin')
        verify_cross_node_roles('couchbaseAdmin')
        verify_cross_node_roles('roadmin')

        if self.compat_mode == '7.6':
            put_user('localUserSecurityAdmin', 'security_admin_local')
            put_user('clusterAdmin', 'cluster_admin')
            verify_cross_node_roles('localUserSecurityAdmin')
            verify_cross_node_roles('clusterAdmin')
        elif self.compat_mode == '8.0':
            put_user('securityAdmin', 'security_admin')
            put_user('localUserAdmin', 'user_admin_local')
            verify_cross_node_roles('securityAdmin')
            verify_cross_node_roles('localUserAdmin')

        old_users = testlib.get_succ(self.old_node, "/settings/rbac/users").json()
        new_users = testlib.get_succ(self.new_node, "/settings/rbac/users").json()
        assert (sorted(u['id'] for u in old_users) ==
                sorted(u['id'] for u in new_users))
        self.user_ids = [u['id'] for u in old_users]

    def post_upgrade_checks(self):
        def verify_roles(username, expected_roles):
            r = testlib.get_succ(
                self.new_node,
                f"/settings/rbac/users/local/{username}").json()
            assert (sorted(item['role'] for item in r['roles']) ==
                    sorted(expected_roles))

        if self.prior_compat_mode == '7.6':
            verify_roles('roadmin-old',
                         ['ro_admin', 'ro_security_admin', 'ui_access'])
            verify_roles('roadmin-new',
                         ['ro_admin', 'ro_security_admin', 'ui_access'])
            verify_roles('localUserSecurityAdmin-old',
                         ['security_admin', 'user_admin_local', 'ui_access'])
            verify_roles('localUserSecurityAdmin-new',
                         ['security_admin', 'user_admin_local', 'ui_access'])
            verify_roles('clusterAdmin-old', ['cluster_admin', 'ui_access'])
            verify_roles('clusterAdmin-new', ['cluster_admin', 'ui_access'])
        elif self.prior_compat_mode == '8.0':
            verify_roles('roadmin-old', ['ro_admin', 'ui_access'])
            verify_roles('roadmin-new', ['ro_admin', 'ui_access'])
            verify_roles('securityAdmin-old', ['security_admin', 'ui_access'])
            verify_roles('securityAdmin-new', ['security_admin', 'ui_access'])
            verify_roles('localUserAdmin-old', ['user_admin_local', 'ui_access'])
            verify_roles('localUserAdmin-new', ['user_admin_local', 'ui_access'])
        else:
            raise AssertionError(
                f"Unexpected prior_compat_mode: {self.prior_compat_mode!r}")

        after = testlib.get_succ(self.new_node, "/settings/rbac/users").json()
        assert sorted(u['id'] for u in after) == sorted(self.user_ids)
        for user_id in self.user_ids:
            testlib.ensure_deleted(self.new_node,
                                   f"/settings/rbac/users/local/{user_id}")


class IndexSettingsUpgradeChecks(UpgradeCheckSuite):

    def before_upgrade(self):
        self.old_index_settings = testlib.get_succ(
            self.old_node, "/settings/indexes").json()

    def mixed_cluster_checks(self):
        # Index settings must be identical on both versions while mixed.
        new_settings = testlib.get_succ(self.new_node, "/settings/indexes").json()
        assert self.compare_json_keys(self.old_index_settings, new_settings,
                                       check_values=True) == []

    def post_upgrade_checks(self):
        new_settings = testlib.get_succ(self.new_node,
                                         "/settings/indexes").json()
        mismatches = self.compare_json_keys(self.old_index_settings, new_settings,
                                             check_values=True)
        if self.prior_compat_mode == '7.6':
            expected = ['deferBuild', 'generateScanReport']
        elif self.prior_compat_mode == '8.0':
            expected = ['generateScanReport']
        else:
            raise AssertionError(
                f"Unexpected prior_compat_mode: {self.prior_compat_mode!r}")
        assert sorted(mismatches) == sorted(expected)


class ClusterCapabilitiesUpgradeChecks(UpgradeCheckSuite):

    def before_upgrade(self):
        self.old_caps = testlib.get_succ(
            self.old_node,
            "/pools/default/nodeServices").json()["clusterCapabilities"]

    def mixed_cluster_checks(self):
        # Cluster compat mode doesn't advance until every node has been
        # upgraded, so clusterCapabilities reported by either node must
        # still match what was seen before the upgrade started.
        for node in (self.old_node, self.new_node):
            caps = testlib.get_succ(
                node,
                "/pools/default/nodeServices").json()["clusterCapabilities"]
            assert caps == self.old_caps, \
                f"clusterCapabilities changed on {node} in a mixed cluster: " \
                f"{caps} vs {self.old_caps}"

    def post_upgrade_checks(self):
        new_caps = testlib.get_succ(
            self.new_node,
            "/pools/default/nodeServices").json()["clusterCapabilities"]

        assert self.compare_json_keys(self.old_caps, new_caps) == []

        n1ql_diff = self.diff_values_for_key("n1ql", self.old_caps, new_caps)
        search_diff = self.diff_values_for_key("search", self.old_caps,
                                               new_caps)
        assert sorted(n1ql_diff) == sorted(['externalCollections',
                                            'conversationalQuery'])
        assert sorted(search_diff) == sorted(['scoreFusion', 'udfQuery'])
