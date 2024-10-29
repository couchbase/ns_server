# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
from multiprocessing import Process


def delete_bucket(node, bucket):
    testlib.ensure_deleted(node, f"/pools/default/buckets/{bucket}")


class BucketDeletionTest(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            min_num_nodes=2,
            buckets=[{"name": f"bucket-{i}",
                      "storageBackend": "couchstore",
                      "replicaNumber": 1,
                      "ramQuota": 100} for i in range(1, 3)]
        )

    def setup(self):
        pass

    def teardown(self):
        # Nuke any testconditions outstanding in case the test failed.
        testlib.post_succ(self.cluster, "/diag/eval",
                          data="testconditions:clear()")

    def concurrent_bucket_deletion_test(self):
        # Delay shutdown of bucket-1 by 5 secs. Testconditions are deleted
        # after they are hit.
        testlib.post_succ(self.cluster, "/diag/eval",
                          data="testconditions:set({wait_for_bucket_shutdown, "
                               "\"bucket-1\"}, {delay, 5000})")

        p = Process(target=delete_bucket,
                    args=(self.cluster.connected_nodes[0], "bucket-1"))
        p.start()
        delete_bucket(self.cluster.connected_nodes[0], "bucket-2")
        p.join()
        assert p.exitcode == 0
