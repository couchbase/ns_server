# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
import requests
import time


def assert_status_code(response, code):
    assert response.status_code == code, \
        f"Different status code: {response.status_code} ({response.text})"


class SampleBucketTestSet(testlib.BaseTestSet):

    def __init__(self):
        self.addr = None
        self.auth = None

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=1, min_memsize=1024,
                                           serverless=True)

    # Send a request with no validation of response
    def request(self, method, endpoint, **kwargs):
        return requests.request(method, endpoint, auth=self.auth,
                                **kwargs)

    def delete_all_buckets(self):
        buckets = self.request('GET', self.addr_buckets)
        for bucket in buckets.json():
            name = bucket['name']
            self.request('DELETE', f"{self.addr_buckets}/{name}")

    def setup(self, cluster):
        self.addr = cluster.urls[0]
        self.addr_get = self.addr + "/sampleBuckets"
        self.addr_post = self.addr_get + "/install"
        self.addr_buckets = self.addr + "/pools/default/buckets"
        self.addr_tasks = self.addr + "/pools/default/tasks"
        self.auth = cluster.auth
        # Deleting existing buckets to make space
        self.delete_all_buckets()

    def teardown(self, cluster):
        # Deleting any remaining buckets
        self.delete_all_buckets()

    # Test the /sampleBuckets endpoint for fetching the list of sample buckets
    def get_test(self, cluster):
        response = self.request('GET', self.addr_get)
        assert_status_code(response, 200)

        for sample in response.json():
            assert "name" in sample, "Missing 'name' property"
            assert "installed" in sample, "Missing 'installed' property"
            assert "quotaNeeded" in sample, "Missing 'quotaNeeded' property"

    # Rather than waiting for the sample bucket to be loaded, we can just check
    # that the task is running
    def assert_loading_sample(self, sample_bucket):
        r = self.request('GET', self.addr_tasks)
        loading = False
        for task in r.json():
            if task.get("type") == "loadingSampleBucket" and \
                    task.get("status") == "running" and \
                    task.get("bucket") == sample_bucket:
                loading = True

        assert loading, f"No loading task for {sample_bucket} in {r.json()}"

    # Loading into a new bucket with the same name as the sample
    def post_without_bucket_name_test(self, cluster):
        sample_bucket = "travel-sample"
        payload = [sample_bucket]
        response = self.request('POST', self.addr_post,
                                json=payload)
        assert_status_code(response, 202)

        # Wait for sample bucket loading to start
        time.sleep(0.5)

        self.assert_loading_sample(sample_bucket)
        self.teardown(cluster)

    # Loading into an existing bucket
    def post_with_existing_bucket_test(self, cluster):
        bucket_name = "test1"
        original_bucket = {"name": bucket_name,
                           "ramQuota": 200}
        response = self.request('POST', self.addr_buckets,
                                data=original_bucket)
        assert_status_code(response, 202)

        # Wait for bucket to be created
        time.sleep(1)

        sample_bucket = "travel-sample"
        payload = [{"sample": sample_bucket,
                    "bucket": bucket_name}]
        response = self.request('POST', self.addr_post,
                                json=payload)
        assert_status_code(response, 202)

        # Wait for sample bucket loading to start
        time.sleep(0.5)

        self.assert_loading_sample(bucket_name)
        self.teardown(cluster)

    # Can't load gamesim-sample in serverless as couchdb is disabled
    def post_with_couchdb_sample_test(self, cluster):
        sample_bucket = "gamesim-sample"
        payload = [sample_bucket]
        response = self.request('POST', self.addr_post,
                                json=payload)
        assert_status_code(response, 400)

    # Loading from http(s):// sample into an existing bucket
    def post_to_http_with_existing_bucket_test(self, cluster):
        bucket_name = "test2"
        original_bucket = {"name": bucket_name,
                           "ramQuota": 200}
        response = self.request('POST', self.addr_buckets,
                                data=original_bucket)
        assert_status_code(response, 202)

        # Wait for bucket to be created
        time.sleep(1)

        # Provide a dummy http(s):// address to attempt to download from
        sample_bucket = "https://dummy-sample-address"
        payload = [{"sample": sample_bucket,
                    "bucket": bucket_name,
                    "http_cache_directory": "/tmp/cache"}]
        response = self.request('POST', self.addr_post,
                                json=payload)
        assert_status_code(response, 202)

        # We can't check if the sample loading has started, because it will
        # immediately fail as we have only provided a dummy http(s)://
        # address
        self.teardown(cluster)

    # Can't create a sample bucket when insufficient total remaining ram quota
    def post_with_insufficient_remaining_ram_quota_test(self, cluster):
        # Create bucket taking up all space
        bucket_name = "test3"
        original_bucket = {"name": bucket_name,
                           "ramQuota": cluster.memsize}
        response = self.request('POST', self.addr_buckets,
                                data=original_bucket)
        assert_status_code(response, 202)

        # Wait for bucket to be created
        time.sleep(1)

        sample_bucket = "travel-sample"
        payload = [sample_bucket]
        response = self.request('POST', self.addr_post,
                                json=payload)
        assert_status_code(response, 400)

        self.teardown(cluster)

    # Can't install to a sample bucket when it has insufficient ram quota
    def post_to_existing_with_insufficient_ram_quota_test(self, cluster):
        bucket_name = "test4"
        original_bucket = {"name": bucket_name,
                           "ramQuota": 100}
        response = self.request('POST', self.addr_buckets,
                                data=original_bucket)
        assert_status_code(response, 202)

        # Wait for bucket to be created
        time.sleep(1)

        sample_bucket = "travel-sample"
        payload = [{"sample": sample_bucket,
                    "bucket": bucket_name}]
        response = self.request('POST', self.addr_post,
                                json=payload)
        assert_status_code(response, 400)
        self.teardown(cluster)
