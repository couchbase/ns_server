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


class ResourceManagementTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        # - Provisioned edition required for guard rails to be configurable
        # - 2 nodes so that we can test that all nodes reject write once the
        #   guard rail has been hit. Note, assert_cant_write will be less likely
        #   to test both nodes if num_nodes increases, so it should be modified
        #   at the same time.
        return testlib.ClusterRequirements(edition="Provisioned", num_nodes=2)

    def setup(self, cluster):
        testlib.delete_all_buckets(cluster)

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        testlib.delete_all_buckets(cluster)
        # Reset guard rail config
        testlib.diag_eval(cluster,
                          "[{resource_management, Cfg}] = "
                          "  menelaus_web_guardrails:default_config(),"
                          "ns_config:set(resource_management, Cfg).")

    def get_guard_rails_test(self, cluster):
        resident_ratio_config = testlib.get_succ(
            cluster, "/settings/resourceManagement/bucket/residentRatio")
        get("enabled", resident_ratio_config)
        get("couchstoreMinimum", resident_ratio_config)
        get("magmaMinimum", resident_ratio_config)

        data_size_config = testlib.get_succ(
            cluster, "/settings/resourceManagement/bucket/dataSizePerNode")
        get("enabled", data_size_config)
        get("couchstoreMaximum", data_size_config)
        get("magmaMaximum", data_size_config)

        cores_per_bucket_config = testlib.get_succ(
            cluster, "/settings/resourceManagement/coresPerBucket")
        get("enabled", cores_per_bucket_config)
        get("minimum", cores_per_bucket_config)

        bucket_config = testlib.get_succ(
            cluster, "/settings/resourceManagement/bucket/collectionsPerQuota")
        get("enabled", bucket_config)
        get("maximum", bucket_config)

        disk_usage_config = testlib.get_succ(
            cluster, "/settings/resourceManagement/diskUsage")
        get("enabled", disk_usage_config)
        get("maximum", disk_usage_config)

    def set_guard_rails_json_test(self, cluster):
        # Set guard rails with json

        r = testlib.post_succ(cluster, "/settings/resourceManagement",
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

    def set_guard_rails_form_test(self, cluster):
        # Set guard rails with form-encoding

        r = testlib.post_succ(
            cluster, "/settings/resourceManagement",
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

    def set_guard_rails_path_test(self, cluster):
        # Set residentRatio guard rail using path

        r = testlib.post_succ(
            cluster, "/settings/resourceManagement/bucket/residentRatio",
            data={
                "enabled": "true",
                "couchstoreMinimum": 7,
                "magmaMinimum": 0.7
            })
        assert get("enabled", r) is True
        assert get("couchstoreMinimum", r) == 7
        assert get("magmaMinimum", r) == 0.7

        r = testlib.post_succ(
            cluster, "/settings/resourceManagement/bucket/dataSizePerNode",
            json={
                "enabled": True,
                "couchstoreMaximum": 34,
                "magmaMaximum": 66
            })
        assert get("enabled", r) is True
        assert get("couchstoreMaximum", r) == 34
        assert get("magmaMaximum", r) == 66

        r = testlib.post_succ(
            cluster, "/settings/resourceManagement/coresPerBucket",
            data={
                "enabled": "true",
                "minimum": 0.4
            })

        assert get("enabled", r) is True
        assert get("minimum", r) == 0.4

        r = testlib.post_succ(
            cluster, "/settings/resourceManagement/diskUsage",
            data={
                "enabled": "true",
                "maximum": 92
            })

        assert get("enabled", r) is True
        assert get("maximum", r) == 92

    def rr_growth_test(self, cluster):
        # Disable other guard rails to ensure we don't get any unexpected
        # guard rails triggered (only seen with disk usage, but disabling all
        # to be extra sure)
        disable_bucket_guard_rails(cluster)

        # Ensure that the guard rail is enabled with a minimum of 10%
        testlib.post_succ(
            cluster, "/settings/resourceManagement/bucket/residentRatio",
            json={
                "enabled": True,
                "couchstoreMinimum": 10,
            })

        cluster.create_bucket({
            "name": "test",
            "ramQuota": 100
        })

        testlib.poll_for_condition(can_write(cluster, "test"),
                                   sleep_time=0.5, attempts=120)

        # Wait for a stat to be populated, as the check will be ignored until we
        # get that stat from prometheus
        wait_for_stat(cluster, "kv_ep_max_size", "test")
        refresh_guard_rails(cluster)
        assert_bucket_resource_status(cluster, "test", "ok")

        # Make sure that we can successfully write to the bucket
        testlib.poll_for_condition(can_write(cluster, "test"),
                                   sleep_time=1, attempts=120,
                                   msg="write to bucket 'test'")

        # Trigger the guard rail by injecting a new promQL query
        # Note, the query uses 'sgn(kv_ep_max_size)' to add a label for the
        # bucket
        testlib.post_succ(cluster, "/internalSettings",
                          data={"resourcePromQLOverride.dataResidentRatio":
                                "9 * sgn(kv_ep_max_size)"})

        refresh_guard_rails(cluster)
        assert_bucket_resource_status(cluster, "test", "resident_ratio")

        # Expect write to fail
        assert_cant_write(cluster, "test",
                          "Ingress disabled due to ratio between per-node "
                          "quota and data size exceeding configured limit")

        # Reset the promQL to verify that the status returns to ok
        testlib.post_succ(cluster, "/internalSettings",
                          data={"resourcePromQLOverride.dataResidentRatio":
                                "11 * sgn(kv_ep_max_size)"})

        refresh_guard_rails(cluster)
        assert_bucket_resource_status(cluster, "test", "ok")

        # Writes should succeed again
        testlib.post_succ(
            cluster, "/pools/default/buckets/test/docs/test_doc",
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


def wait_for_stat(cluster, stat, bucket=None, n=1):

    def got_stats():
        params = stats_range_common_params()
        if bucket is not None:
            params["bucket"] = bucket
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
