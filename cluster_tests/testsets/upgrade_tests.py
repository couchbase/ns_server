# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""
Upgrade checks grouped by feature area, driven by a single UpgradeChecks
testset.

UpgradeChecks runs one upgrade cycle and calls each check suite in turn at
each phase:

    Phase 1  before_upgrade()       – old-version cluster; capture state
    Phase 3  mixed_cluster_checks() – both versions active; cross-version checks
    Phase 5  post_upgrade_checks()  – new-version cluster; verify final state

To add a new check suite, subclass UpgradeCheckSuite, implement the three
hooks, and add the class to UpgradeChecks._check_classes.

Available on self within hook methods:
  self.old_node / self.new_node   representative nodes for each version
  self.compat_mode                current compat mode (updates after upgrade)
  self.prior_compat_mode          compat mode before upgrade
                                  (set at start of phase 5)
  self.bucket_name                name of the pre-created test bucket
"""

import testlib
from testlib.upgrade_test_base import UpgradeChecks as UpgradeCheckSuite
from testsets.example_upgrade_checks import ExampleUpgradeChecks


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
                    'crl_expired']
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
                    'crl_expired']
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


class UpgradeChecks(testlib.BaseTestSet):
    """Drives upgrade check suites through a single upgrade cycle.

    Use --tests UpgradeChecks to run all check suites.
    """

    _check_classes = [
        AlertsUpgradeChecks,
        BucketSettingsUpgradeChecks,
        RbacRolesUpgradeChecks,
        RbacRoleChangesUpgradeChecks,
        IndexSettingsUpgradeChecks,
        ExampleUpgradeChecks,
    ]

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            min_num_nodes=2,
            balanced=True,
            num_vbuckets=16,
            # Puts mixed_version=True into start_args so that
            # cluster.build_cluster routes through legacy_cluster to start
            # old-version nodes.  Requires --older-version-path to be supplied.
            mixed_version=True,
            buckets=[{"name": "upgradeTestBucket",
                      "storageBackend": "couchstore",
                      "replicaNumber": 1,
                      "ramQuota": 100}])

    def setup(self):
        self.bucket_name = "upgradeTestBucket"

    def test_teardown(self):
        pass

    def teardown(self):
        # is_met() assumes a cluster still satisfies its requirements once a
        # testset has finished, so that the cluster can be reused by a later
        # testset. upgrade_test() leaves the cluster in a state that no
        # longer satisfies the mixed_version requirement (whether or not it
        # ran to completion), so mark it as spent here rather than only on
        # the success path, ensuring it isn't handed to another testset
        # expecting a fresh mixed-version cluster.
        self.cluster.new_version_nodes = []
        self.cluster.set_requirements(None)

    def upgrade_test(self):
        check_classes = self._check_classes

        old_nodes = list(self.cluster.connected_nodes)
        new_nodes = self.cluster.new_version_nodes
        old_node = old_nodes[0]
        new_node = new_nodes[0]

        checks = [cls() for cls in check_classes]

        def set_attrs(**kwargs):
            for check in checks:
                for k, v in kwargs.items():
                    setattr(check, k, v)

        set_attrs(cluster=self.cluster,
                  old_nodes=old_nodes, new_nodes=new_nodes,
                  old_node=old_node, new_node=new_node,
                  bucket_name=self.bucket_name)

        # ------------------------------------------------------------------
        # Phase 1: old-version-only cluster
        # ------------------------------------------------------------------
        compat_mode = self._verify_cluster_info(mixed=False)
        set_attrs(compat_mode=compat_mode)
        for check in checks:
            check.before_upgrade()

        # ------------------------------------------------------------------
        # Phase 2: join new-version nodes and rebalance in
        # ------------------------------------------------------------------
        # Join each new-version node with the same services as its
        # corresponding old-version node, rather than relying on add_node's
        # default (which would pick up the services of whichever connected
        # node happens to handle the addNode request).
        for old_node_, new_node_ in zip(old_nodes, new_nodes):
            self.cluster.add_node(new_node_, services=old_node_.get_services())
        self.cluster.rebalance(wait=True)

        # ------------------------------------------------------------------
        # Phase 3: mixed cluster
        # ------------------------------------------------------------------
        self._verify_cluster_info(mixed=True)
        for check in checks:
            check.mixed_cluster_checks()

        # ------------------------------------------------------------------
        # Phase 4: rebalance out old-version nodes
        # ------------------------------------------------------------------
        prior_compat_mode = compat_mode
        self.cluster.rebalance(ejected_nodes=list(old_nodes),
                               wait=True, verbose=True,
                               node=new_node)

        # ------------------------------------------------------------------
        # Phase 5: new-version-only cluster
        # ------------------------------------------------------------------
        compat_mode = self._verify_cluster_info(mixed=False)
        assert prior_compat_mode != compat_mode, \
            f"Compat mode did not change after upgrade " \
            f"(still {compat_mode!r})"
        set_attrs(compat_mode=compat_mode, prior_compat_mode=prior_compat_mode)
        for check in checks:
            check.post_upgrade_checks()

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _verify_cluster_info(self, mixed):
        """Assert cluster health and return the compat mode string.

        When mixed=True, asserts exactly two node versions are present.
        When mixed=False, asserts all nodes run the same version.
        Always asserts a single compat mode, all nodes healthy and active.
        """
        pools = testlib.get_succ(self.cluster, "/pools/default").json()
        assert pools["balanced"]
        versions = {}
        compat_modes = {}
        for node in pools["nodes"]:
            compat = node["clusterCompatibility"]
            compat_str = f"{compat >> 16}.{compat & 0xFFFF}"
            print(f">>> Node {node['hostname']} version={node['version']} "
                  f"compat={compat_str} status={node['status']} "
                  f"membership={node['clusterMembership']} <<<")
            assert node["status"] == "healthy"
            assert node["clusterMembership"] == "active"
            versions[node["version"]] = versions.get(node["version"], 0) + 1
            compat_modes[compat_str] = compat_modes.get(compat_str, 0) + 1

        if mixed:
            assert len(versions) == 2, \
                f"Expected 2 versions in mixed cluster, got {list(versions)}"
        else:
            assert len(versions) == 1, \
                f"Expected 1 version in uniform cluster, got {list(versions)}"
        assert len(compat_modes) == 1, \
            f"Expected single compat mode, got {compat_modes}"
        return next(iter(compat_modes))
