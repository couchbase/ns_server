# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib


class ResourceManagementTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Provisioned", num_nodes=1)

    def setup(self, cluster):
        pass

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        pass

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


def get(key, response):
    url = response.url
    j = testlib.json_response(response, f"Response to {url} is not json")
    return testlib.assert_json_key(key, j, url)
