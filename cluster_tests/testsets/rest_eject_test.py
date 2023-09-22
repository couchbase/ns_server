# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import testlib


class RestEjectTest(testlib.BaseTestSet):
    def __init__(self, cluster):
        super().__init__(cluster)

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=3)

    def setup(self):
        testlib.delete_all_buckets(self.cluster)
        bucket = {"name": "testbucket", "ramQuota": "200"}

        self.cluster.create_bucket(bucket)

    def teardown(self):
        testlib.delete_all_buckets(self.cluster)

    def rest_reject_test(self):
        nodes = self.cluster.connected_nodes
        otp_nodes = testlib.get_otp_nodes(self.cluster)
        failoverNode = nodes[0]
        otp_name = otp_nodes[failoverNode.hostname()]

        self.cluster.failover_node(failoverNode, graceful=False)

        # Eject failed over node via REST endpoint and verify it can be
        # added back in after ejection
        data = {"otpNode": f"{otp_name}"}
        testlib.post_succ(self.cluster.nodes[1], '/controller/ejectNode',
                          data=data)
        self.cluster.rebalance(wait=True)
        self.cluster.add_node(failoverNode)
        self.cluster.rebalance(wait=True)

        # The previously failed over ejected node was added back in
        # and should not be allowed to be ejected because it is active
        testlib.post_fail(self.cluster.nodes[1], '/controller/ejectNode',
                          expected_code=400, data=data)
