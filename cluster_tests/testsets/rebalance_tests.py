#!/usr/bin/env python3
#
# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
import testlib.util

from testlib import ClusterRequirements, Service

class KVRebalanceTests(testlib.BaseTestSet):
    @staticmethod
    def requirements():
        return [ClusterRequirements(edition="Enterprise",
                                    min_num_nodes=3, num_connected=2,
                                    buckets=[{"name": f"couchstore",
                                              "storageBackend": "couchstore",
                                              "replicaNumber":1,
                                              "ramQuota": 100}],
                                    exact_services=[Service.KV])]

    def __init__(self, cluster):
        super().__init__(cluster)

    def setup(self):
        testlib.post_succ(self.cluster, "/internalSettings",
                          data={"fileBasedBackfillEnabled": "true"})
        pass

    def teardown(self):
        testlib.post_succ(self.cluster, "/internalSettings",
                          data={"fileBasedBackfillEnabled": "false"})

        if (len(self.cluster.connected_nodes) < 2):
            # We should never have 0 nodes, so just add one back.
            self.cluster.add_node(self.cluster.disconnected_nodes()[0],
                                  wait=True)
        elif (len(self.cluster.connected_nodes) > 2):
            # Remove all but 2 nodes, bringing us back to the original state.
            self.cluster.rebalance(
                ejected_nodes = self.cluster.connected_nodes[2:],
                wait=True)

    # This is really 3 tests:
    # 1. Rebalance in
    # 2. Rebalance out
    # 3. Swap rebalance
    #
    # This is run as a single test because we do not want to reset the cluster
    # between each test, it wastes time and /should/ not be needed.
    def file_based_rebalance_test(self):
        RebalanceSuccess = self.cluster.get_counter("rebalance_success")

        NodeToAdd = self.cluster.disconnected_nodes()[0]
        self.cluster.add_node(NodeToAdd, do_rebalance=True)
        RebalanceSuccess += 1
        self.cluster.poll_for_counter_value("rebalance_success",
                                            RebalanceSuccess)

        self.cluster.smog_check()

        NodeToRemove = self.cluster.connected_nodes[2]
        self.cluster.rebalance(ejected_nodes=[NodeToRemove], wait=True)
        RebalanceSuccess += 1
        self.cluster.poll_for_counter_value("rebalance_success",
                                            RebalanceSuccess)
        self.cluster.smog_check()

        NodeToAdd = self.cluster.disconnected_nodes()[0]
        NodeToRemove = self.cluster.connected_nodes[1]
        self.cluster.add_node(NodeToAdd)
        self.cluster.rebalance(ejected_nodes=[NodeToRemove], wait=True)

        RebalanceSuccess += 1
        self.cluster.poll_for_counter_value("rebalance_success",
                                            RebalanceSuccess)

        self.cluster.smog_check()
