# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
from tasks_test import TasksBase


# 20 second timeout for sample bucket loading. cbimport shouldn't take any
# longer than this
CBIMPORT_TIMEOUT = 20


class SampleBucketTestSet(testlib.BaseTestSet, TasksBase):

    def __init__(self, cluster):
        super().__init__(cluster)
        self.addr_buckets = None
        self.addr_post = None
        self.addr_get = None

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise",
                                           min_memsize=1024)

    def setup(self, cluster):
        self.addr_get = "/sampleBuckets"
        self.addr_post = self.addr_get + "/install"
        self.addr_buckets = "/pools/default/buckets"
        self.addr_tasks = "/pools/default/tasks"

        # Deleting existing buckets to make space
        testlib.delete_all_buckets(cluster)

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        # Deleting any remaining buckets
        testlib.delete_all_buckets(cluster)

    # Create a bucket with name and ram_quota specified
    def create_bucket(self, name, ram_quota=200):
        bucket = {"name": name, "ramQuota": ram_quota}
        testlib.post_succ(self.cluster, self.addr_buckets, 202, data=bucket)

    # Test the /sampleBuckets endpoint for fetching the list of sample buckets
    def get_test(self, cluster):
        response = testlib.get_succ(cluster, self.addr_get)
        samples = testlib.json_response(response,
                                        "/sampleBuckets returned invalid json")
        for sample in samples:
            for key in ["name", "installed", "quotaNeeded"]:
                testlib.assert_json_key(key, sample, self.addr_get)

    # Extract a single task description from the response to a request to the
    # /sampleBuckets/install endpoint. Assumes that the request only provided
    # one sample bucket to be loaded
    def get_task_desc_from_response(self, response):
        json = testlib.json_response(response, f"{self.addr_post} "
                                               "returned invalid json")

        tasks = testlib.assert_json_key("tasks", json, self.addr_post)

        assert len(tasks) == 1, f"Unexpected number of task objects in " \
                                f"{self.addr_post} response: {len(json)}"
        return tasks[0]

    # To determine that the sample was loaded, we wait for the task status
    # to become "completed"
    def assert_loaded_sample(self, response, timeout):
        task_desc = self.get_task_desc_from_response(response)
        self.assert_task_status(task_desc, "completed", timeout)

    # To determine that the sample failed to load, we wait for the task status
    # to become "failed"
    def assert_sample_load_failed(self, response, timeout):
        task_desc = self.get_task_desc_from_response(response)
        self.assert_task_status(task_desc, "failed", timeout)

    # Wait for the task's status to become expected_last_status, failing the
    # test if timeout is reached
    def assert_task_status(self, task_desc, expected_last_status, timeout):
        # Generate the expected final task status from the task description
        task_id = testlib.assert_json_key("taskId", task_desc, self.addr_post)
        sample_bucket = testlib.assert_json_key("bucket", task_desc,
                                                self.addr_post)
        expected_task = self.Task(task_id, "loadingSampleBucket",
                                  expected_last_status, sample_bucket, {})

        def loading_done(task):
            if task is None:
                return False
            else:
                return task.get("status") == expected_last_status

        # Wait for the task to satisfy loading_done
        fetched_task = self.wait_for_task(self.cluster, task_id, loading_done,
                                          timeout)

        # Assert that the final task is as expected
        self.assert_tasks_equal(fetched_task, expected_task)

    # Test that we can load into a new bucket, which will have the same name as
    # the specified sample
    def post_without_existing_bucket_test(self, cluster):
        sample_bucket = "travel-sample"
        payload = [sample_bucket]
        response = testlib.post_succ(cluster, self.addr_post, 202, json=payload)

        # Double the timeout to allow for bucket creation
        self.assert_loaded_sample(response, CBIMPORT_TIMEOUT * 2)

    # Test loading into an existing bucket
    def post_with_existing_bucket_test(self, cluster):
        bucket_name = "test1"
        self.create_bucket(bucket_name)

        sample_bucket = "travel-sample"
        payload = [{"sample": sample_bucket,
                    "bucket": bucket_name}]
        response = testlib.post_succ(cluster, self.addr_post, 202, json=payload)

        self.assert_loaded_sample(response, CBIMPORT_TIMEOUT)

    # Test loading from http(s):// sample into an existing bucket
    def post_to_http_with_existing_bucket_test(self, cluster):
        bucket_name = "test2"
        self.create_bucket(bucket_name)

        # Provide a dummy http(s):// address to attempt to download from
        sample_bucket = "https://dummy-sample-address"
        payload = [{"sample": sample_bucket,
                    "bucket": bucket_name,
                    "http_cache_directory": "/tmp/cache"}]
        response = testlib.post_succ(cluster, self.addr_post, 202, json=payload)

        # We check for task failed instead of completed, because it will
        # immediately fail since we have only provided a dummy http(s)://
        # address
        self.assert_sample_load_failed(response, CBIMPORT_TIMEOUT)

    # Confirm that loading a sample bucket fails when there is insufficient
    # total remaining ram quota
    def post_with_insufficient_remaining_ram_quota_test(self, cluster):
        # Create bucket taking up all space
        bucket_name = "test3"
        self.create_bucket(bucket_name, cluster.memsize)

        # Loading a sample bucket should fail when the cluster has insufficient
        # ram quota
        sample_bucket = "travel-sample"
        payload = [sample_bucket]
        testlib.post_fail(cluster, self.addr_post, 400, json=payload)

    # Confirm that loading sample data into an existing bucket fails when the
    # bucket has insufficient ram quota
    def post_to_existing_with_insufficient_ram_quota_test(self, cluster):
        bucket_name = "test4"
        self.create_bucket(bucket_name, 100)

        # Loading a sample bucket should fail when the bucket has insufficient
        # ram quota
        sample_bucket = "travel-sample"
        payload = [{"sample": sample_bucket,
                    "bucket": bucket_name}]
        testlib.post_fail(cluster, self.addr_post, 400, json=payload)

    def post_with_couchdb_sample_test(self, cluster):
        sample_bucket = "gamesim-sample"
        payload = [sample_bucket]
        # Confirm that loading gamesim-sample succeeds when not in
        # serverless, as couchdb is enabled
        response = testlib.post_succ(cluster, self.addr_post, 202,
                                     json=payload)
        # Double the timeout to allow for bucket creation
        self.assert_loaded_sample(response, CBIMPORT_TIMEOUT * 2)


class ServerlessSampleBucketTestSet(SampleBucketTestSet):

    def __init__(self, cluster):
        super().__init__(cluster)
        self.addr_buckets = None
        self.addr_post = None
        self.addr_get = None

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Serverless",
                                           min_memsize=1024)

    # Confirm that loading gamesim-sample fails in serverless, as
    # couchdb is disabled. This test overrides the corresponding
    # non-serverless test
    def post_with_couchdb_sample_test(self, cluster):
        sample_bucket = "gamesim-sample"
        payload = [sample_bucket]
        testlib.post_fail(cluster, self.addr_post, 400, json=payload)
