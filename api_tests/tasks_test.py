# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib

import time
import itertools
from copy import copy


class TasksBase:
    class Task:
        def __init__(self, task_id, task_type, status, bucket, extras):
            self.task_id = task_id
            self.task_type = task_type
            self.status = status
            self.bucket = bucket
            self.extras = extras

    def __init__(self):
        self.addr_pools_default = "/pools/default"
        self.addr_tasks = self.addr_pools_default + "/tasks"

    def get_status_address(self, task_id):
        return f"{self.addr_tasks}?taskId={task_id}"

    def get_task_status(self, cluster, task_id):
        status_address = self.get_status_address(task_id)
        # Fetch the task status
        r = testlib.get_succ(cluster, status_address)

        # Attempt to decode the response
        tasks = testlib.json_response(r, "Task status was not json")

        assert len(tasks) == 1, \
            f"Unexpected number of tasks in response to '{status_address}': " \
            f"{len(tasks)}"

        return tasks[0]

    # Wait for the task identified by task_id to satisfy is_task_done or reach
    # the timeout limit
    def wait_for_task(self, cluster, task_id, is_task_done, timeout):
        def get_status():
            return self.get_task_status(cluster, task_id)
        # Wait until timeout reached
        time_start = time.time()
        timeout_time = time_start + timeout
        while not is_task_done(last_task_status := get_status()) and \
                time.time() < timeout_time:
            # Sleep for a 20th of the total timeout, so that we only make at
            # most 20 checks, rather than spamming the cluster
            time.sleep(timeout / 20)

        timeout_msg = f"Task status check timed out after {timeout}s. \n"

        assert last_task_status is not None, \
            f"{timeout_msg}" \
            f"No task found with task_id '{task_id}'"

        assert is_task_done(last_task_status), \
            f"{timeout_msg}" \
            f"Last task status:\n{last_task_status}"

        return last_task_status

    @staticmethod
    def assert_tasks_equal(found_task, expected_task):
        # Check the task type, status, bucket, and extras are correct
        assert found_task.get("task_id") == expected_task.task_id, \
            f"Task id '{found_task.get('task_id')}' found, expected " \
            f"'{expected_task.task_id}'"
        assert found_task.get("type") == expected_task.task_type, \
            f"Task type '{found_task.get('type')}' found, expected " \
            f"'{expected_task.task_type}'"
        assert found_task.get("status") == expected_task.status, \
            f"Task status '{found_task.get('status')}' found, expected " \
            f"'{expected_task.status}'"
        assert found_task.get("bucket") == expected_task.bucket, \
            f"Bucket '{found_task.get('bucket')}' found, expected " \
            f"'{expected_task.bucket}'"
        assert found_task.get("extras") == expected_task.extras, \
            f"Task extras '{found_task.get('extras')}' found, expected " \
            f"'{expected_task.extras}'"

    # Assert that the task can be fetched with ?taskId= and that the status is
    # as expected
    def assert_task(self, cluster, expected_task):
        found_task = self.get_task_status(cluster, expected_task.task_id)
        self.assert_tasks_equal(found_task, expected_task)

        # Assert whether or not the task shows up in the
        # /pools/default/tasks endpoint
        if self.is_default_task(expected_task):
            self.assert_task_in_default_list(cluster, expected_task)
        else:
            self.assert_task_not_in_default_list(cluster, expected_task)

    @staticmethod
    # Determines whether a task should be expected in the default response of
    # /pools/default/tasks
    def is_default_task(task):
        return task.status == "running"

    # Assert that can the expected task can be found in the tasks list given by
    # /pools/default/tasks
    def assert_task_in_default_list(self, cluster, expected_task):
        expected_id = expected_task.task_id

        # Fetch tasks
        r = testlib.get_succ(cluster, self.addr_tasks)

        # Attempt to decode the response
        tasks = testlib.json_response(r, "Tasks list was not json")

        for found_task in tasks:
            if found_task.get("task_id") == expected_id:
                self.assert_tasks_equal(found_task, expected_task)
                return

        assert False, f"Task id '{expected_id} not found in tasks list:\n" \
                      f"{tasks}"

    # Assert that a task is not included in the tasks list given by
    # /pools/default/tasks
    def assert_task_not_in_default_list(self, cluster, unexpected_task):
        unexpected_id = unexpected_task.task_id

        # Fetch tasks
        r = testlib.get_succ(cluster, self.addr_tasks)

        # Attempt to decode the response
        tasks = testlib.json_response(r, "Tasks list was not json")

        for found_task in tasks:
            assert found_task.get("task_id") != unexpected_id, \
                f"Unexpected task found with task_id '{unexpected_id}"

    # Get the current tasks list version
    def get_tasks_version(self, cluster):
        r = testlib.get_succ(cluster, self.addr_pools_default)
        json_resp = testlib.json_response(r, f"{self.addr_pools_default} "
                                             f"response was not json")
        tasks = testlib.assert_json_key("tasks", json_resp,
                                        self.addr_pools_default)
        uri = testlib.assert_json_key("uri", tasks, self.addr_pools_default)

        # Tasks version is provided by the 'v' key in the uri's query string
        assert "?v=" in uri, "Missing tasks hash in uri"
        return uri.split("?v=")[1]

    def assert_tasks_version_changed(self, cluster, old_version):
        new_version = self.get_tasks_version(cluster)
        assert new_version != old_version, \
            f"Tasks version was not changed when expected"
        # Return the new version, for subsequent comparisons without re-fetching
        return new_version

    def assert_tasks_version_same(self, cluster, old_version):
        new_version = self.get_tasks_version(cluster)
        assert new_version == old_version, \
            f"Unexpected change of tasks version"


def task_to_erlang(task):
    if task.bucket is None:
        bucket = "undefined"
    else:
        bucket = f"\"{task.bucket}\""

    extras_body = ",".join([f"{{{key}, {value}}}"
                            for key, value in task.extras.items()])
    extras = f"[{extras_body}]"

    return f"<<\"{task.task_id}\">>,{task.task_type},{task.status}," \
           f"{bucket},{extras}"


class TasksTestSet(testlib.BaseTestSet, TasksBase):
    def __init__(self, cluster):
        testlib.BaseTestSet.__init__(self, cluster)
        TasksBase.__init__(self)
        self.addr_diag_eval = "/diag/eval"
        self.task_types = ["loadingSampleBucket", "rebalance"]
        self.statuses = ["queued", "running", "completed", "failed"]
        self.bucket_names = ["default", "test", None]
        self.extras_values = [{}, {"test": "value"}]

    def setup(self, cluster):
        pass

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=1, min_memsize=1024)

    def teardown(self, cluster):
        pass

    # Generate a task with random task id
    def generate_task(self, task_type, status, bucket, extras):
        return self.Task(testlib.random_str(8), task_type, status, bucket,
                         extras)

    # Manually create a task by diag eval, to test global_tasks generically
    def update_task(self, cluster, task):
        testlib.post_succ(cluster,
                          self.addr_diag_eval,
                          data=f"global_tasks:update_task("
                               f"{task_to_erlang(task)}).")

    # Generate valid task updates by modifying the status in all possible ways,
    # then modifying the extras field in all possible ways
    def generate_task_updates(self, task):
        # Copy the task so that we can modify it without impacting the original
        new_task = copy(task)
        # Yield a new task with each status other than the existing one
        for status in self.statuses:
            if status != task.status:
                new_task.status = status
                yield new_task
        # Yield a new task with each value of extras other than the existing one
        for extras in self.extras_values:
            if extras != task.status:
                new_task.extras = extras
                yield new_task

    # Attempt to update a task with a sequence of valid changes
    def test_updating_task(self, cluster, initial_task, version):
        last_task = initial_task
        for task_update in self.generate_task_updates(initial_task):
            self.update_task(cluster, task_update)
            self.assert_task(cluster, task_update)

            # If the task_update and last_task are either both default tasks
            # or both not default tasks, then version should be the same
            if self.is_default_task(task_update) == \
                    self.is_default_task(last_task):
                # Assert that the tasks version is unaffected by an update to an
                # existing task
                self.assert_tasks_version_same(cluster, version)
            else:
                # If exactly one of task_update and last_task are default tasks
                # then the task will either be added or removed from the
                # default tasks list, so the version should change
                version = self.assert_tasks_version_changed(cluster, version)
            last_task = task_update

        # Return the final version for use in subsequent comparisons
        return version

    # Generate a variety of tasks.
    # These are not necessarily valid tasks, but should still be accepted
    def generate_tasks(self):
        test_tasks = itertools.product(self.task_types, self.statuses,
                                       self.bucket_names, self.extras_values)
        for task_type, status, bucket, extras in test_tasks:
            yield self.generate_task(task_type, status, bucket, extras)

    def simple_test(self, cluster):
        version = self.get_tasks_version(cluster)
        for task in self.generate_tasks():
            # Add a new task and assert that it was added
            self.update_task(cluster, task)
            self.assert_task(cluster, task)

            if self.is_default_task(task):
                # If we add a new task to the default tasks list, then the
                # version should change
                version = self.assert_tasks_version_changed(cluster, version)
                # Test that subsequent task updates correctly impact the version
                version = self.test_updating_task(cluster, task, version)

