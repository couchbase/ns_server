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
from testlib.upgrade.strategies.delta import DeltaRecoveryUpgradeSuite
from testlib.upgrade.strategies.offline import OfflineUpgradeSuite
from testlib.upgrade.strategies.online import OnlineUpgradeSuite
from testlib.upgrade.suite import UpgradeCheckSuite
# Imported for its side effect: the engine discovers suites in any module
# under testsets/, and this one is not in run.py's import list.
from testsets import example_upgrade_checks  # noqa: F401
from testsets import jwt_upgrade_checks  # noqa: F401


class _AlertsUpgradeChecks(UpgradeCheckSuite,
                           OnlineUpgradeSuite,
                           OfflineUpgradeSuite,
                           DeltaRecoveryUpgradeSuite):
    """/settings/alerts across the upgrade."""

    reads = frozenset({'settings/alerts'})

    # The alert names that differ between this source version and the version
    # under test, as a symmetric difference.
    EXPECTED_DIFF = None

    # Whether the two nodes of a mixed cluster report the same enabled-alert
    # lists.
    MIXED_LISTS_AGREE = True

    def before_upgrade(self):
        self.old_alerts = testlib.get_succ(self.old_node,
                                            "/settings/alerts").json()

    def mixed_cluster_checks(self):
        new_alerts = testlib.get_succ(self.new_node, "/settings/alerts").json()
        assert self.compare_json_keys(self.old_alerts, new_alerts) == []
        if self.MIXED_LISTS_AGREE:
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
            assert sorted(mismatches) == sorted(self.EXPECTED_DIFF)


class AlertsUpgradeChecksFrom80(_AlertsUpgradeChecks):
    from_version = '8.0'

    # Alerts added after 8.0.
    EXPECTED_DIFF = [
        'encr_at_rest_key_test_failed',
        'encr_at_rest_errors_total',
        'xdcr_replication_deleted',
        'cm_bucket_autoreprovision_total',
        'backup_failure',
        'cont_backup_event_failed',
        'cont_backup_gaps',
        'crl_expires_soon',
        'crl_unusable']


class AlertsUpgradeChecksFrom76(_AlertsUpgradeChecks):
    from_version = '7.6'

    # The 8.x node exposes its own alert definitions (alerts added and removed
    # relative to 7.6) whatever the compat mode, so the lists do not agree
    # until the upgrade completes; post_upgrade_checks verifies the delta.
    MIXED_LISTS_AGREE = False

    # Alerts added after 7.6, plus the one 8.0 removed (stuck_rebalance).
    EXPECTED_DIFF = [
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


class _BucketSettingsUpgradeChecks(UpgradeCheckSuite,
                                   OnlineUpgradeSuite,
                                   OfflineUpgradeSuite,
                                   DeltaRecoveryUpgradeSuite):
    """The test bucket's settings across the upgrade."""

    reads = frozenset({'bucket:shared'})
    writes = frozenset({'buckets'})

    MEMCACHED_BODY = {"name": "memcachedBucket",
                      "bucketType": "memcached",
                      "ramQuota": 100}
    NEW_MEMCACHED_ERROR = {"bucketType":
                           "memcached buckets are no longer supported"}

    # Bucket properties the source version exposes and the version under test
    # does not, or the other way round, as a symmetric difference.
    MIXED_DIFF = []
    EXPECTED_DIFF = None

    # assert_source_rejection(body): how the source version words its
    # rejection of a memcached bucket.
    assert_source_rejection = None

    @property
    def path(self):
        return f"/pools/default/buckets/{self.bucket_name}"

    def before_upgrade(self):
        self.old_bucket_info = testlib.get_succ(self.old_node,
                                                self.path).json()

    def mixed_cluster_checks(self):
        new_bucket_info = testlib.get_succ(self.new_node, self.path).json()
        mismatches = self.compare_json_keys(self.old_bucket_info,
                                            new_bucket_info)
        assert sorted(mismatches) == sorted(self.MIXED_DIFF)

        # Memcached buckets must be rejected by both versions.
        r = testlib.post_fail(self.old_node, "/pools/default/buckets",
                              expected_code=400,
                              data=self.MEMCACHED_BODY).json()
        self.assert_source_rejection(r)

        r = testlib.post_fail(self.new_node, "/pools/default/buckets",
                              expected_code=400,
                              data=self.MEMCACHED_BODY).json()
        assert r['errors'] == self.NEW_MEMCACHED_ERROR

    def post_upgrade_checks(self):
        new_bucket_info = testlib.get_succ(self.new_node, self.path).json()
        mismatches = self.compare_json_keys(self.old_bucket_info,
                                            new_bucket_info)
        assert sorted(mismatches) == sorted(self.EXPECTED_DIFF)


class BucketSettingsUpgradeChecksFrom80(_BucketSettingsUpgradeChecks):
    from_version = '8.0'

    # Properties added after 8.0.
    EXPECTED_DIFF = [
            'chronicleRev', 'dataServiceRebalanceType',
            'continuousBackupCloudStorageCredId',
            'continuousBackupKmCredId', 'continuousBackupKmKeyUrl',
            'continuousBackupLocation', 'continuousBackupInterval',
            'continuousBackupRetentionPeriod',
            'externalCollectionsManifestUid', 'throttleHardLimit',
            'throttleReserved']

    def assert_source_rejection(self, body):
        assert body['errors'] == self.NEW_MEMCACHED_ERROR


class BucketSettingsUpgradeChecksFrom76(_BucketSettingsUpgradeChecks):
    from_version = '7.6'

    MIXED_DIFF = ['pitrEnabled', 'pitrGranularity', 'pitrMaxHistoryAge']

    EXPECTED_DIFF = [
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

    def assert_source_rejection(self, body):
        assert body == {'_': 'memcached buckets are no longer supported'}


class _RbacRolesUpgradeChecks(UpgradeCheckSuite,
                              OnlineUpgradeSuite,
                              OfflineUpgradeSuite,
                              DeltaRecoveryUpgradeSuite):
    """The set of defined roles across the upgrade."""

    reads = frozenset({'rbac/roles'})

    # Role names the source version and the version under test differ on, as a
    # symmetric difference.
    EXPECTED_DIFF = None

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
        assert sorted(mismatches) == sorted(self.EXPECTED_DIFF)


class RbacRolesUpgradeChecksFrom80(_RbacRolesUpgradeChecks):
    from_version = '8.0'

    # Roles added after 8.0.
    EXPECTED_DIFF = ['ui_access', 'credential_consumer', 'credential_admin',
                     'external_catalog_admin', 'external_catalog_reader']


class RbacRolesUpgradeChecksFrom76(_RbacRolesUpgradeChecks):
    from_version = '7.6'

    EXPECTED_DIFF = [
        'user_admin_external', 'ro_security_admin',
        'credential_admin',
        'application_telemetry_writer', 'query_manage_system_catalog',
        'ui_access', 'security_admin', 'query_list_index',
        'user_admin_local', 'security_admin_local',
        'security_admin_external', 'credential_consumer',
        'external_catalog_admin', 'external_catalog_reader']


class _RbacRoleChangesUpgradeChecks(UpgradeCheckSuite,
                                    OnlineUpgradeSuite,
                                    DeltaRecoveryUpgradeSuite):
    """A user's roles across the upgrade, and across the version boundary.

    Not offline: the users are created in the mixed cluster, one copy from
    each version, because half of what this checks is that the two versions
    agree about a user the other one created. An offline upgrade has no
    mixed cluster to create them in; a delta-recovery one does.
    """

    reads = frozenset({'rbac/roles'})
    writes = frozenset({'rbac/users'})

    # Users every source version can be given.
    COMMON_USERS = {'couchbaseAdmin': 'admin', 'roadmin': 'ro_admin'}

    # Users only this source version knows the roles for.
    EXTRA_USERS = {}

    # What each user's roles must be once the upgrade is done, keyed by the
    # name without the -old/-new suffix: both copies expect the same.
    EXPECTED_ROLES = {}

    def before_upgrade(self):
        self.created = []

    def users(self):
        return {**self.COMMON_USERS, **self.EXTRA_USERS}

    def mixed_cluster_checks(self):
        # Users created on one version must be visible with identical roles
        # on the other version.
        def put_user(username, roles):
            for node, suffix in [(self.old_node, 'old'),
                                 (self.new_node, 'new')]:
                user_id = self.name(f"{username}-{suffix}")
                testlib.put_succ(
                    node,
                    f"/settings/rbac/users/local/{user_id}",
                    data={'roles': roles, 'password': testlib.random_str(8)})
                self.created.append(user_id)
                self.delete_on_cleanup(
                    f"/settings/rbac/users/local/{user_id}")

        def verify_cross_node_roles(username):
            on_old = testlib.get_succ(
                self.old_node,
                f"/settings/rbac/users/local/"
                f"{self.name(username + '-new')}").json()
            on_new = testlib.get_succ(
                self.new_node,
                f"/settings/rbac/users/local/"
                f"{self.name(username + '-old')}").json()
            assert (sorted(r['role'] for r in on_old['roles']) ==
                    sorted(r['role'] for r in on_new['roles']))

        for username, roles in self.users().items():
            put_user(username, roles)
        for username in self.users():
            verify_cross_node_roles(username)

        # Only this suite's own users: the listing is cluster-wide and shared
        # with every other suite on this cluster.
        assert (self._our_user_ids(self.old_node) ==
                self._our_user_ids(self.new_node) ==
                set(self.created))

    def _our_user_ids(self, node):
        users = testlib.get_succ(node, "/settings/rbac/users").json()
        return {u['id'] for u in users if self.owns(u['id'])}

    def post_upgrade_checks(self):
        def verify_roles(username, expected_roles):
            r = testlib.get_succ(
                self.new_node,
                f"/settings/rbac/users/local/{self.name(username)}").json()
            assert (sorted(item['role'] for item in r['roles']) ==
                    sorted(expected_roles))

        for username, expected in self.EXPECTED_ROLES.items():
            verify_roles(f"{username}-old", expected)
            verify_roles(f"{username}-new", expected)

        assert self._our_user_ids(self.new_node) == set(self.created)


class RbacRoleChangesUpgradeChecksFrom76(_RbacRoleChangesUpgradeChecks):
    from_version = '7.6'

    EXTRA_USERS = {'localUserSecurityAdmin': 'security_admin_local',
                   'clusterAdmin': 'cluster_admin'}

    EXPECTED_ROLES = {
        'couchbaseAdmin': ['admin'],
        'roadmin': ['ro_admin', 'ro_security_admin', 'ui_access'],
        'localUserSecurityAdmin': ['security_admin', 'user_admin_local',
                                   'ui_access'],
        'clusterAdmin': ['cluster_admin', 'ui_access'],
    }


class RbacRoleChangesUpgradeChecksFrom80(_RbacRoleChangesUpgradeChecks):
    from_version = '8.0'

    EXTRA_USERS = {'securityAdmin': 'security_admin',
                   'localUserAdmin': 'user_admin_local'}

    EXPECTED_ROLES = {
        'couchbaseAdmin': ['admin'],
        'roadmin': ['ro_admin', 'ui_access'],
        'securityAdmin': ['security_admin', 'ui_access'],
        'localUserAdmin': ['user_admin_local', 'ui_access'],
    }


class _IndexSettingsUpgradeChecks(UpgradeCheckSuite,
                                  OnlineUpgradeSuite,
                                  OfflineUpgradeSuite,
                                  DeltaRecoveryUpgradeSuite):
    """/settings/indexes across the upgrade."""

    reads = frozenset({'settings/indexes'})

    # Settings the source version and the version under test differ on, by
    # key or by value.
    EXPECTED_DIFF = None

    def before_upgrade(self):
        self.old_index_settings = testlib.get_succ(
            self.old_node, "/settings/indexes").json()

    def mixed_cluster_checks(self):
        # Index settings must be identical on both versions while mixed.
        new_settings = testlib.get_succ(self.new_node,
                                        "/settings/indexes").json()
        assert self.compare_json_keys(self.old_index_settings, new_settings,
                                       check_values=True) == []

    def post_upgrade_checks(self):
        new_settings = testlib.get_succ(self.new_node,
                                         "/settings/indexes").json()
        mismatches = self.compare_json_keys(self.old_index_settings,
                                            new_settings, check_values=True)
        assert sorted(mismatches) == sorted(self.EXPECTED_DIFF)


class IndexSettingsUpgradeChecksFrom80(_IndexSettingsUpgradeChecks):
    from_version = '8.0'

    EXPECTED_DIFF = ['generateScanReport']


class IndexSettingsUpgradeChecksFrom76(_IndexSettingsUpgradeChecks):
    from_version = '7.6'

    EXPECTED_DIFF = ['deferBuild', 'generateScanReport']


class ClusterCapabilitiesUpgradeChecks(UpgradeCheckSuite,
                                       OnlineUpgradeSuite,
                                       OfflineUpgradeSuite,
                                       DeltaRecoveryUpgradeSuite):
    # No from_version: 7.6 and 8.0 differ from the version under test by the
    # same capabilities.
    reads = frozenset({'pools/default/nodeServices'})

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
