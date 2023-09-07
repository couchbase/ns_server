# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
from pprint import pprint

import testlib


class ResourceManagementAPITests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        # - Provisioned edition required for guard rails to be configurable
        return testlib.ClusterRequirements(edition="Provisioned")

    def setup(self):
        # Set the promQL queries to default values to ensure that they are
        # triggered consistently
        set_promql_queries(self.cluster)

    def teardown(self):
        pass

    def test_teardown(self):
        # Reset guard rail config
        testlib.diag_eval(self.cluster,
                          "[{resource_management, Cfg}] = "
                          "  menelaus_web_guardrails:default_config(),"
                          "ns_config:set(resource_management, Cfg).")

    def get_guard_rails_test(self):
        resident_ratio_config = testlib.get_succ(
            self.cluster, "/settings/resourceManagement/bucket/residentRatio")
        get("enabled", resident_ratio_config)
        get("couchstoreMinimum", resident_ratio_config)
        get("magmaMinimum", resident_ratio_config)

        data_size_config = testlib.get_succ(
            self.cluster, "/settings/resourceManagement/bucket/dataSizePerNode")
        get("enabled", data_size_config)
        get("couchstoreMaximum", data_size_config)
        get("magmaMaximum", data_size_config)

        cores_per_bucket_config = testlib.get_succ(
            self.cluster, "/settings/resourceManagement/coresPerBucket")
        get("enabled", cores_per_bucket_config)
        get("minimum", cores_per_bucket_config)

        bucket_config = testlib.get_succ(
            self.cluster,
            "/settings/resourceManagement/bucket/collectionsPerQuota")
        get("enabled", bucket_config)
        get("maximum", bucket_config)

        disk_usage_config = testlib.get_succ(
            self.cluster, "/settings/resourceManagement/diskUsage")
        get("enabled", disk_usage_config)
        get("maximum", disk_usage_config)

    def set_guard_rails_json_test(self):
        # Set guard rails with json

        r = testlib.post_succ(self.cluster, "/settings/resourceManagement",
                              json={
                                  "bucket": {
                                      "residentRatio": {
                                          "enabled": True,
                                          "couchstoreMinimum": 5,
                                          "magmaMinimum": 0.5
                                      },
                                      "dataSizePerNode": {
                                          "enabled": True,
                                          "couchstoreMaximum": 32,
                                          "magmaMaximum": 64
                                      },
                                      "collectionsPerQuota": {
                                          "enabled": True,
                                          "maximum": 2
                                      }
                                  },
                                  "coresPerBucket": {
                                      "enabled": True,
                                      "minimum": 0.2
                                  },
                                  "diskUsage": {
                                      "enabled": True,
                                      "maximum": 90
                                  }
                              })

        bucket_config = get("bucket", r)

        resident_ratio_config = bucket_config.get("residentRatio")
        assert resident_ratio_config.get("enabled") is True
        assert resident_ratio_config.get("couchstoreMinimum") == 5
        assert resident_ratio_config.get("magmaMinimum") == 0.5

        data_size_config = bucket_config.get("dataSizePerNode")
        assert data_size_config.get("enabled") is True
        assert data_size_config.get("couchstoreMaximum") == 32
        assert data_size_config.get("magmaMaximum") == 64

        collections_config = bucket_config.get("collectionsPerQuota")
        assert collections_config.get("enabled") is True
        assert collections_config.get("maximum") == 2

        data_disk_usage_config = get("diskUsage", r)
        assert data_disk_usage_config.get("enabled") is True
        assert data_disk_usage_config.get("maximum") == 90

        cores_per_bucket_config = get("coresPerBucket", r)
        assert cores_per_bucket_config.get("enabled") is True
        assert cores_per_bucket_config.get("minimum") == 0.2

    def set_guard_rails_form_test(self):
        # Set guard rails with form-encoding

        r = testlib.post_succ(
            self.cluster, "/settings/resourceManagement",
            data={
                "bucket.residentRatio.enabled": "false",
                "bucket.residentRatio.couchstoreMinimum": 6,
                "bucket.residentRatio.magmaMinimum": 0.6,
                "bucket.dataSizePerNode.enabled": "false",
                "bucket.dataSizePerNode.couchstoreMaximum": 33,
                "bucket.dataSizePerNode.magmaMaximum": 65,
                "bucket.collectionsPerQuota.enabled": "false",
                "bucket.collectionsPerQuota.maximum": 3,
                "coresPerBucket.enabled": "false",
                "coresPerBucket.minimum": 0.3,
                "diskUsage.enabled": "false",
                "diskUsage.maximum": 91
            })

        bucket_config = get("bucket", r)

        resident_ratio_config = bucket_config.get("residentRatio")
        assert resident_ratio_config.get("enabled") is False
        assert resident_ratio_config.get("couchstoreMinimum") == 6
        assert resident_ratio_config.get("magmaMinimum") == 0.6

        data_size_config = bucket_config.get("dataSizePerNode")
        assert data_size_config.get("enabled") is False
        assert data_size_config.get("couchstoreMaximum") == 33
        assert data_size_config.get("magmaMaximum") == 65

        collections_config = bucket_config.get("collectionsPerQuota")
        assert collections_config.get("enabled") is False
        assert collections_config.get("maximum") == 3

        assert get("coresPerBucket", r).get("enabled") is False
        assert get("coresPerBucket", r).get("minimum") == 0.3

        assert get("diskUsage", r).get("enabled") is False
        assert get("diskUsage", r).get("maximum") == 91

    def set_guard_rails_path_test(self):
        # Set residentRatio guard rail using path

        r = testlib.post_succ(
            self.cluster, "/settings/resourceManagement/bucket/residentRatio",
            data={
                "enabled": "true",
                "couchstoreMinimum": 7,
                "magmaMinimum": 0.7
            })
        assert get("enabled", r) is True
        assert get("couchstoreMinimum", r) == 7
        assert get("magmaMinimum", r) == 0.7

        r = testlib.post_succ(
            self.cluster, "/settings/resourceManagement/bucket/dataSizePerNode",
            json={
                "enabled": True,
                "couchstoreMaximum": 34,
                "magmaMaximum": 66
            })
        assert get("enabled", r) is True
        assert get("couchstoreMaximum", r) == 34
        assert get("magmaMaximum", r) == 66

        r = testlib.post_succ(
            self.cluster, "/settings/resourceManagement/coresPerBucket",
            data={
                "enabled": "true",
                "minimum": 0.4
            })

        assert get("enabled", r) is True
        assert get("minimum", r) == 0.4

        r = testlib.post_succ(
            self.cluster, "/settings/resourceManagement/diskUsage",
            data={
                "enabled": "true",
                "maximum": 92
            })

        assert get("enabled", r) is True
        assert get("maximum", r) == 92


class GuardRailRestrictionTests(testlib.BaseTestSet):

    def __init__(self, cluster):
        super().__init__(cluster)
        self.original_max_supported = None
        self.original_promql = None

    @staticmethod
    def requirements():
        # - Provisioned edition required for guard rails to be configurable
        # - 2 nodes so that we can test rebalances
        # - 1024MB quota for magma bucket
        return testlib.ClusterRequirements(edition="Provisioned",
                                           min_num_nodes=2, num_connected=2,
                                           min_memsize=1024)

    def setup(self):
        testlib.delete_all_buckets(self.cluster)

        # Get original settings, so that they can be set back on teardown
        original_settings = testlib.get_succ(self.cluster, "/internalSettings")\
            .json()
        self.original_max_supported = original_settings \
            .get("maxBucketCount", 30)
        self.original_promql = original_settings .get("resourcePromQLOverride")

    def teardown(self):
        testlib.delete_all_buckets(self.cluster)

        # Set back modified internal settings to their original values
        testlib.post_succ(self.cluster, "/internalSettings",
                          data={"maxBucketCount": self.original_max_supported,
                                **{f"resourcePromQLOverride.{key}": value
                                   for key, value in
                                   self.original_promql.items()}})

        response = testlib.get_succ(self.cluster, "/internalSettings").json()
        assert response.get("maxBucketCount") == self.original_max_supported
        assert response.get("resourcePromQLOverride") == self.original_promql, \
            f"failed to reset resourcePromQLOverride to " \
            f"{self.original_promql}, got from /internalSettings: {response}"

    def test_teardown(self):
        testlib.delete_all_buckets(self.cluster)
        # Reset the promQL queries to default values to ensure that they are
        # triggered consistently
        set_promql_queries(self.cluster)

    def num_buckets_test(self):
        pools = testlib.get_succ(self.cluster, "/pools/default").json()
        cpu_count = pools["nodes"][0]["cpuCount"]

        # Set minimum cores per bucket to N times the cpu count, permitting
        # exactly N buckets (where N = max_buckets_dynamic)
        for max_buckets_dynamic in range(1, 4):
            testlib.post_succ(self.cluster,
                              "/settings/resourceManagement/coresPerBucket",
                              json={
                                  "enabled": True,
                                  "minimum": cpu_count / max_buckets_dynamic
                              })

            # Set the hard limit just above the dynamic limit
            max_buckets_supported = max_buckets_dynamic + 1
            testlib.post_succ(self.cluster, "/internalSettings",
                              data={"maxBucketCount": max_buckets_supported})

            # Create the permitted buckets
            for i in range(max_buckets_dynamic):
                self.cluster.create_bucket({
                    "name": f"test_{i}",
                    "ramQuota": 100
                })

            # Test that an additional bucket can't be created and gives the
            # expected error message, mentioning the per-core limit
            r = self.cluster.create_bucket(
                {
                    "name": "test_too_many",
                    "ramQuota": 100
                }, expected_code=400)
            exp_error = f"Cannot create more than {max_buckets_dynamic} " \
                        f"buckets due to insufficient cpu cores. Either " \
                        f"increase the resource minimum or the number of " \
                        f"cores on all kv nodes."
            assert r.json()['_'] == exp_error, \
                f"{r.json()['_']} != {exp_error}"

            # Disable the per-core limit
            testlib.post_succ(self.cluster,
                              "/settings/resourceManagement/coresPerBucket",
                              json={
                                  "enabled": False
                              })

            # One more bucket allowed
            self.cluster.create_bucket({
                "name": f"test_{cpu_count}",
                "ramQuota": 100
            })

            # Test that no more buckets are allowed, and we now get the old
            # error message
            r = self.cluster.create_bucket(
                {
                    "name": "test_too_many_again",
                    "ramQuota": 100
                }, expected_code=400)
            exp_error = f"Cannot create more than {max_buckets_supported} " \
                        f"buckets"
            assert r.json()["_"] == exp_error, \
                f"{r.json()['_']} != {exp_error}"

            # Delete the buckets in preparation for the next test case
            testlib.delete_all_buckets(self.cluster)

    def rebalance_test(self):
        self.cluster.create_bucket({
            "name": "test",
            "ramQuota": 100
        })

        # Ensure that the guard rail is enabled with a minimum of 10%
        testlib.post_succ(
            self.cluster, "/settings/resourceManagement/bucket/residentRatio",
            json={
                "enabled": True,
                "couchstoreMinimum": 10,
            })

        # Trigger the guard rail by injecting a new promQL query to set the
        # per-node data size to 8 times the quota, s.t. quota/size = 12.5%.
        # With a RR% of 12.5, removing a node takes the RR below 10%
        set_promql_queries(self.cluster, data_size_bytes=800_000_000)

        self.cluster.rebalance(
            ejected_nodes=[self.cluster.connected_nodes[1]],
            initial_code=400,
            initial_expected_error=
            '{"rr_will_be_too_low":"The following buckets are expected to '
            'breach the resident ratio minimum: test"}')

    def storage_migration_test(self):
        # Test migration from couchstore to magma
        self.cluster.create_bucket({
            "name": "test",
            "ramQuota": 1024,
            "storageBackend": "couchstore"
        })

        # Ensure that the appropriate guard rails have expected limits
        testlib.post_succ(
            self.cluster, "/settings/resourceManagement/bucket/",
            json={
                "residentRatio": {
                    "enabled": True,
                    "couchstoreMinimum": 10
                },
                "dataSizePerNode": {
                    "enabled": True,
                    "couchstoreMaximum": 1.6,
                }
            })

        # Test that we can't perform bucket migration from couchstore to magma
        # when the bucket doesn't satisfy the couchstore limits
        set_promql_queries(self.cluster, data_size_tb=10, resident_ratio=5)
        resp = self.cluster.update_bucket({
            "name": "test",
            "storageBackend": "magma"
        }, expected_code=400).json()
        assert resp.get("errors", {}).get("storageBackend") == \
               "Storage mode migration is not allowed when data size per node" \
               " is above the configured maximum: 1.6TB", \
               f"Unexpected errors: {resp}"

        # Test that we can't perform bucket migration from couchstore to magma
        # when the bucket doesn't satisfy the couchstore data size limit
        set_promql_queries(self.cluster, data_size_tb=10, resident_ratio=15)
        resp = self.cluster.update_bucket({
            "name": "test",
            "storageBackend": "magma"
        }, expected_code=400).json()
        assert resp.get("errors", {}).get("storageBackend") == \
               "Storage mode migration is not allowed when data size per node" \
               " is above the configured maximum: 1.6TB", \
               f"Unexpected errors: {resp}"

        # Test that we can't perform bucket migration from couchstore to magma
        # when the bucket doesn't satisfy the couchstore resident ratio limit
        set_promql_queries(self.cluster, data_size_tb=1, resident_ratio=5)
        resp = self.cluster.update_bucket({
            "name": "test",
            "storageBackend": "magma"
        }, expected_code=400).json()
        assert resp.get("errors", {}).get("storageBackend") == \
               "Storage mode migration is not allowed when resident ratio is " \
               "below the configured minimum: 10%", f"Unexpected errors: {resp}"

        # Test that we can perform bucket migration from couchstore to magma
        # when the bucket satisfies the couchstore limits
        set_promql_queries(self.cluster, data_size_tb=1, resident_ratio=15)

        self.cluster.update_bucket({
            "name": "test",
            "storageBackend": "magma"
        })

        # Test migration back from magma to couchstore

        # Test that we can't perform bucket migration from magma to couchstore
        # when the bucket doesn't satisfy the couchstore limits
        set_promql_queries(self.cluster, data_size_tb=10, resident_ratio=5)
        resp = self.cluster.update_bucket({
            "name": "test",
            "storageBackend": "couchstore"
        }, expected_code=400).json()
        assert resp.get("errors", {}).get("storageBackend") == \
               "Storage mode migration is not allowed when data size per node" \
               " is above the configured maximum: 1.6TB", \
               f"Unexpected errors: {resp}"

        # Test that we can't perform bucket migration from magma to couchstore
        # when the bucket doesn't satisfy the couchstore data size limit
        set_promql_queries(self.cluster, data_size_tb=10, resident_ratio=15)
        resp = self.cluster.update_bucket({
            "name": "test",
            "storageBackend": "couchstore"
        }, expected_code=400).json()
        assert resp.get("errors", {}).get("storageBackend") == \
               "Storage mode migration is not allowed when data size per node" \
               " is above the configured maximum: 1.6TB", \
               f"Unexpected errors: {resp}"

        # Test that we can't perform bucket migration from magma to couchstore
        # when the bucket doesn't satisfy the couchstore resident ratio limit
        set_promql_queries(self.cluster, data_size_tb=1, resident_ratio=5)
        resp = self.cluster.update_bucket({
            "name": "test",
            "storageBackend": "couchstore"
        }, expected_code=400).json()
        assert resp.get("errors", {}).get("storageBackend") == \
               "Storage mode migration is not allowed when resident ratio is " \
               "below the configured minimum: 10%", f"Unexpected errors: {resp}"

        # Test that we can perform bucket migration from couchstore to magma
        # when the bucket satisfies the couchstore limits
        set_promql_queries(self.cluster, data_size_tb=1, resident_ratio=15)

        self.cluster.update_bucket({
            "name": "test",
            "storageBackend": "couchstore"
        })


class DataIngressTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        # - Provisioned edition required for guard rails to be configurable
        # - 2 nodes so that we can test that all nodes reject write once the
        #   guard rail has been hit. Note, assert_cant_write will be less likely
        #   to test both nodes if num_nodes increases, so it should be modified
        #   at the same time.
        return testlib.ClusterRequirements(edition="Provisioned",
                                           min_num_nodes=2, num_connected=2)

    def setup(self):
        testlib.delete_all_buckets(self.cluster)
        self.cluster.create_bucket({
            "name": "test",
            "ramQuota": 100
        })

    def teardown(self):
        testlib.delete_all_buckets(self.cluster)

    def test_teardown(self):
        # Reset the promQL queries to default values to ensure that they are
        # triggered consistently
        set_promql_queries(self.cluster)
        # Ensure that if the node removal was incorrectly permitted, we can run
        # further tests, by adding the node back in
        if len(self.cluster.connected_nodes) < 2:
            spare_nodes = [node for node in self.cluster.nodes
                           if node not in self.cluster.connected_nodes]
            assert len(spare_nodes) >= 1
            node = spare_nodes[0]
            self.cluster.add_node(node, do_rebalance=True)

    def rr_growth_test(self):
        # Disable other guard rails to ensure we don't get any unexpected
        # guard rails triggered (only seen with disk usage, but disabling all
        # to be extra sure)
        disable_bucket_guard_rails(self.cluster)

        # Ensure that the guard rail is enabled with a minimum of 10%
        testlib.post_succ(
            self.cluster, "/settings/resourceManagement/bucket/residentRatio",
            json={
                "enabled": True,
                "couchstoreMinimum": 10,
            })

        testlib.poll_for_condition(can_write(self.cluster, "test"),
                                   sleep_time=0.5, attempts=120)

        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "ok")

        # Make sure that we can successfully write to the bucket
        testlib.poll_for_condition(can_write(self.cluster, "test"),
                                   sleep_time=1, attempts=120,
                                   msg="write to bucket 'test'")

        # Trigger the guard rail by setting the resident ratio below the minimum
        set_promql_queries(self.cluster, resident_ratio=9)

        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "resident_ratio")

        # Expect write to fail
        assert_cant_write(self.cluster, "test",
                          "Ingress disabled due to ratio between per-node "
                          "quota and data size exceeding configured limit")

        # Reset the promQL to verify that the status returns to ok
        set_promql_queries(self.cluster, resident_ratio=100)

        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "ok")

        # Writes should succeed again
        testlib.post_succ(
            self.cluster, "/pools/default/buckets/test/docs/test_doc",
            data="")

    def data_size_growth_test(self):
        # Disable other guard rails to ensure we don't get any unexpected
        # guard rails triggered (only seen with disk usage, but disabling all
        # to be extra sure)
        disable_bucket_guard_rails(self.cluster)

        # Ensure that the guard rail is enabled
        testlib.post_succ(
            self.cluster, "/settings/resourceManagement/bucket/dataSizePerNode",
            json={
                "enabled": True,
                "couchstoreMaximum": 1,
            })

        testlib.poll_for_condition(is_warmed_up(self.cluster, "test"),
                                   sleep_time=0.5, attempts=120)

        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "ok")

        # Make sure that we can successfully write to the cluster
        testlib.poll_for_condition(can_write(self.cluster, "test"),
                                   sleep_time=0.5, attempts=120)

        # Set the data size above the maximum
        set_promql_queries(self.cluster, data_size_tb=2)

        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "data_size")

        # Expect write to fail
        assert_cant_write(self.cluster, "test",
                          "Ingress disabled due to data size exceeding "
                          "configured limit")

        # Set the data size below the maximum, to verify that the status goes
        # back to ok
        set_promql_queries(self.cluster, data_size_tb=0.5)

        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "ok")

        # Writes should succeed again
        testlib.post_succ(
            self.cluster, "/pools/default/buckets/test/docs/test_doc",
            data="")

    def disk_usage_growth_test(self):
        # Disable other guard rails to ensure we don't get any unexpected
        # guard rails triggered (only seen with disk usage, but disabling all
        # to be extra sure)
        disable_bucket_guard_rails(self.cluster)

        # Ensure that the guard rail is enabled, and set the limit high to avoid
        # false positives
        testlib.post_succ(
            self.cluster, "/settings/resourceManagement/diskUsage",
            json={
                "enabled": True,
                "maximum": 85,
            })

        testlib.poll_for_condition(is_warmed_up(self.cluster, "test"),
                                   sleep_time=0.5, attempts=120)

        # Wait for a stat to be populated, as the check will be ignored until we
        # get that stat from prometheus
        wait_for_stat(self.cluster, "sys_disk_usage_ratio", n=2)
        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "ok")

        # Make sure that we can successfully write to the cluster
        testlib.poll_for_condition(can_write(self.cluster, "test"),
                                   sleep_time=0.5, attempts=120)

        # Set disk usage above the maximum
        set_promql_queries(self.cluster, disk_usage=90)

        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "disk_usage")

        # Expect write to fail
        assert_cant_write(self.cluster, "test",
                          "Ingress disabled due to disk usage exceeding "
                          "configured limit")

        # Set the disk usage back to 0, to verify the status goes back to ok
        set_promql_queries(self.cluster, disk_usage=0)

        refresh_guard_rails(self.cluster)
        assert_bucket_resource_status(self.cluster, "test", "ok")

        # Writes should succeed again
        testlib.post_succ(
            self.cluster, "/pools/default/buckets/test/docs/test_doc",
            data="")


def disable_bucket_guard_rails(cluster):
    testlib.post_succ(
        cluster, "/settings/resourceManagement/",
        json={
            "bucket": {
                "residentRatio": {
                    "enabled": False
                },
                "dataSizePerNode": {
                    "enabled": False
                }
            },
            "diskUsage": {
                "enabled": False
            },
        })


# Set promQL queries such that they give fixed values, rather than depending on
# the cluster state. The default values are such that no guard rails will fire
def set_promql_queries(cluster, data_size_tb=.0, data_size_bytes=0,
                       disk_usage=0, resident_ratio=100, bucket="test"):
    # Create a fake metric with a bucket label
    bucket_metric_base = f'label_replace(up, "bucket", "{bucket}", "", "")'

    testlib.post_succ(cluster, "/internalSettings",
                      data={"resourcePromQLOverride.dataSizePerNodeTB":
                            f"{data_size_tb} * {bucket_metric_base}",
                            "resourcePromQLOverride.dataSizePerNodeBytes":
                            f"{data_size_bytes} * {bucket_metric_base}",
                            "resourcePromQLOverride.diskUsage":
                            f"{disk_usage} * sgn(sys_disk_usage_ratio)",
                            "resourcePromQLOverride.dataResidentRatio":
                            f"{resident_ratio} * {bucket_metric_base}"})


def assert_bucket_resource_status(cluster, bucket, expected_status):
    status = get_bucket_status(cluster, bucket)
    assert status == expected_status, \
        f"Bucket '{bucket}' status was '{status}'. Expected '{expected_status}'"


def is_warmed_up(cluster, bucket):
    def f():
        r = testlib.get_succ(cluster, f"/pools/default/buckets/{bucket}")
        return all(node.get("status") == "healthy"
                   for node in r.json().get("nodes", []))
    return f


def can_write(cluster, bucket):
    def f():
        r = testlib.post(
            cluster, f"/pools/default/buckets/{bucket}/docs/test_doc",
            data="")
        return r.status_code == 200
    return f


def assert_cant_write(cluster, bucket, exp_error):
    # Test 10 random keys, in order to likely test writing to both nodes
    for i in range(10):
        j = testlib.random_str(10)
        r = testlib.post_fail(
            cluster, f"/pools/default/buckets/{bucket}/docs/{j}",
            data="", expected_code=400)
        reason = r.json().get("reason")
        assert exp_error == reason, \
            f"Got unexpected error reason on write: '{reason}'. " \
            f"Expected '{exp_error}'"


def wait_for_stat(cluster, stat, n=1):

    def got_stats():
        params = stats_range_common_params()
        data = range_api_get(cluster, stat,
                             params=params)
        return len(data) >= n

    testlib.poll_for_condition(got_stats, 1, attempts=60,
                               msg=f"Wait for stat '{stat}' to be on {n} nodes")


def stats_range_common_params():
    return {'start': - 10,
            'step': 1}


def range_api_get(cluster, stat, params=None):
    if params is None:
        params = {}
    r = testlib.get_succ(
          cluster,
          f'/pools/default/stats/range/{stat}',
          params=params)
    r = r.json()
    print('stats res: ')
    pprint(r)
    return r['data']


def refresh_guard_rails(cluster):
    # Force each node's guardrail monitor to check for status changes
    for node in cluster.connected_nodes:
        testlib.diag_eval(node, "guardrail_monitor ! check,"
                                "gen_server:call(guardrail_monitor, sync).")

    node = cluster.wait_for_orchestrator()
    # Wait for the enforcer to handle the config updates
    testlib.diag_eval(node, "ns_config:sync(), "
                            "gen_server:call(guardrail_enforcer, sync).")


def get_bucket_status(cluster, bucket_name):
    node = cluster.wait_for_orchestrator()
    # Get the bucket status according to the orchestrator
    r = testlib.diag_eval(node,
                          f"guardrail_enforcer:get_status({{bucket, "
                          f"\"{bucket_name}\"}}).")
    return r.text


def get(key, response):
    url = response.url
    j = testlib.json_response(response, f"Response to {url} is not json")
    return testlib.assert_json_key(key, j, url)
