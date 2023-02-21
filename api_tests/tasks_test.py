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

    def simple_test(self, cluster):
        # Test a variety of task updates
        # These are not necessarily valid tasks, but should still be accepted
        for task_type in ["loadingSampleBucket", "rebalance"]:
            for status in ["queued", "running", "completed", "failed"]:
                for bucket in ["default", "test", None]:
                    for extras in [{}, {"test": "value"}]:
                        task = self.generate_task(task_type, status, bucket,
                                                  extras)
                        self.update_task(cluster, task)
                        self.assert_task(cluster, task)
