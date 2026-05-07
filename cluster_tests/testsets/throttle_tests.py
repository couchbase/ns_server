# @author Couchbase <info@couchbase.com>
# @copyright 2025-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included
# in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
# in that file, in accordance with the Business Source License, use of
# this software will be governed by the Apache License, Version 2.0,
# included in the file licenses/APL2.txt.

import testlib

BUCKETS_ENDPOINT = "/pools/default/buckets"
MCD_GLOBAL_ENDPOINT = "/pools/default/settings/memcached/global"
MCD_NODE_ENDPOINT = "/pools/default/settings/memcached/node"
MCD_EFFECTIVE_ENDPOINT = "/pools/default/settings/memcached/effective"
MAX_64BIT = 2**64 - 1

class ThrottleTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            num_nodes=2, min_memsize=256,
            balanced=True, edition="Enterprise",
            buckets=[])

    def setup(self):
        self.node = self.cluster.connected_nodes[0].otp_node()

    def teardown(self):
        pass

    def test_teardown(self):
        for b in self.cluster.get_buckets():
            self.cluster.delete_bucket(b["name"])
        testlib.post_succ(
            self.cluster, MCD_GLOBAL_ENDPOINT,
            data={"node_capacity": str(MAX_64BIT)}, expected_code=202)
        node_ep = f"{MCD_NODE_ENDPOINT}/{self.node}"
        testlib.delete(self.cluster, f"{node_ep}/setting/node_capacity")

    def _create_bucket(self, name, reserved=0, hard_limit=MAX_64BIT,
                       expected_code=202):
        data = {
            "name": name,
            "ramQuota": 100,
            "replicaNumber": 0,
            "bucketType": "couchbase",
            "throttleReserved": reserved,
            "throttleHardLimit": hard_limit,
        }
        return testlib.request(
            'POST', self.cluster, BUCKETS_ENDPOINT, data=data,
            expected_code=expected_code)

    def _update_bucket(self, name, **kwargs):
        data = {}
        if "reserved" in kwargs:
            data["throttleReserved"] = kwargs["reserved"]
        if "hard_limit" in kwargs:
            data["throttleHardLimit"] = kwargs["hard_limit"]
        return testlib.request(
            'POST', self.cluster, f"{BUCKETS_ENDPOINT}/{name}", data=data)

    def _get_bucket(self, name):
        return testlib.get_succ(
            self.cluster, f"{BUCKETS_ENDPOINT}/{name}").json()

    def _set_global_node_capacity(self, capacity):
        return testlib.request(
            'POST', self.cluster, MCD_GLOBAL_ENDPOINT,
            data={"node_capacity": str(capacity)})

    def _set_node_capacity(self, node, capacity):
        return testlib.request(
            'POST', self.cluster,
            f"{MCD_NODE_ENDPOINT}/{node}",
            data={"node_capacity": str(capacity)})

    def _get_effective(self, node):
        return testlib.get_succ(
            self.cluster, f"{MCD_EFFECTIVE_ENDPOINT}/{node}").json()

    # --- Bucket throttle constraint tests ---

    def create_and_update_bucket_reserved_within_limit_test(self):
        """reserved < hard_limit on create and update => ok"""
        self._create_bucket("b1", reserved=100, hard_limit=200)
        info = self._get_bucket("b1")
        testlib.assert_eq(100, info.get("throttleReserved"))
        testlib.assert_eq(200, info.get("throttleHardLimit"))
        self.cluster.wait_for_bucket("b1")
        r = self._update_bucket("b1", reserved=150, hard_limit=200)
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        info = self._get_bucket("b1")
        testlib.assert_eq(150, info.get("throttleReserved"))

    def create_and_update_bucket_reserved_equals_limit_test(self):
        """reserved == hard_limit on create, then
        update reserved > hard_limit => 400"""
        self._create_bucket("b1", reserved=500, hard_limit=500)
        info = self._get_bucket("b1")
        testlib.assert_eq(500, info.get("throttleReserved"))
        testlib.assert_eq(500, info.get("throttleHardLimit"))
        self.cluster.wait_for_bucket("b1")
        r = self._update_bucket("b1", reserved=600, hard_limit=500)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"


    def create_bucket_failures_test(self):
        """All bucket creation failure cases"""
        # reserved > hard_limit => 400
        r = self._create_bucket("b1", reserved=300, hard_limit=200,
                                expected_code=400)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"

        # reserved > global capacity => 400
        r = self._set_global_node_capacity(500)
        assert r.status_code == 202
        r = self._create_bucket("b1", reserved=600, hard_limit=1000,
                                expected_code=400)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"

        # sum of reserved > capacity => 400
        self._create_bucket("b1", reserved=300, hard_limit=1000)
        self.cluster.wait_for_bucket("b1")
        r = self._create_bucket("b2", reserved=300, hard_limit=1000,
                                expected_code=400)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"
        self.cluster.delete_bucket("b1")

        # per-node capacity overrides global => 400
        r = self._set_global_node_capacity(2000)
        assert r.status_code == 202
        r = self._set_node_capacity(self.node, 100)
        assert r.status_code == 202
        r = self._create_bucket("b1", reserved=200, hard_limit=2000,
                                 expected_code=400)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"

    def create_bucket_zero_reserved_test(self):
        """reserved=0 always ok"""
        self._create_bucket("b1", reserved=0, hard_limit=1)

    def create_bucket_defaults_test(self):
        """Defaults: reserved=0, hard_limit=MAX"""
        data = {
            "name": "b1",
            "ramQuota": 100,
            "replicaNumber": 0,
            "bucketType": "couchbase",
        }
        testlib.post_succ(self.cluster, BUCKETS_ENDPOINT,
                          data=data, expected_code=202)
        info = self._get_bucket("b1")
        testlib.assert_eq(0, info.get("throttleReserved"))
        testlib.assert_eq(MAX_64BIT, info.get("throttleHardLimit"))

    # --- Capacity vs reserved constraint tests ---


    def create_and_update_capacity_test(self):
        """Create bucket with reserved <= capacity, then update reserved to
        exceed capacity => 400"""
        r = self._set_global_node_capacity(500)
        assert r.status_code == 202
        self._create_bucket("b1", reserved=400, hard_limit=1000)
        self.cluster.wait_for_bucket("b1")
        r = self._update_bucket("b1", reserved=600)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"

    # --- Global mcd config constraint tests ---

    def reduce_global_capacity_blocked_test(self):
        """Reduce global capacity below total reserved across buckets =>
        error"""
        r = self._set_global_node_capacity(1000)
        assert r.status_code == 202
        self._create_bucket("b1", reserved=400, hard_limit=1000)
        self.cluster.wait_for_bucket("b1")
        self._create_bucket("b2", reserved=400, hard_limit=1000)
        self.cluster.wait_for_bucket("b2")
        r = self._set_global_node_capacity(500)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"

    def reduce_global_capacity_allowed_test(self):
        """Reduce global capacity to >= total reserved => ok"""
        r = self._set_global_node_capacity(1000)
        assert r.status_code == 202
        self._create_bucket("b1", reserved=200, hard_limit=1000)
        self.cluster.wait_for_bucket("b1")
        r = self._set_global_node_capacity(300)
        assert r.status_code == 202

    # --- Per-node mcd config constraint tests ---

    def reduce_node_capacity_blocked_test(self):
        """Reduce per-node capacity below total reserved => error"""
        r = self._set_global_node_capacity(2000)
        assert r.status_code == 202
        self._create_bucket("b1", reserved=500, hard_limit=2000)
        self.cluster.wait_for_bucket("b1")
        r = self._set_node_capacity(self.node, 300)
        assert r.status_code == 400, f"Expected 400, got {r.status_code}"

    def reduce_node_capacity_allowed_test(self):
        """Reduce per-node capacity to >= total reserved  => ok"""
        r = self._set_global_node_capacity(2000)
        assert r.status_code == 202
        self._create_bucket("b1", reserved=200, hard_limit=2000)
        self.cluster.wait_for_bucket("b1")
        r = self._set_node_capacity(self.node, 500)
        assert r.status_code == 202

    def effective_settings_test(self):
        """Verify effective settings reflect global and per-node overrides"""
        r = self._set_global_node_capacity(5000)
        assert r.status_code == 202
        eff = self._get_effective(self.node)
        testlib.assert_eq(5000, eff.get("node_capacity"))

        r = self._set_node_capacity(self.node, 3000)
        assert r.status_code == 202
        eff = self._get_effective(self.node)
        testlib.assert_eq(3000, eff.get("node_capacity"))

    def global_settings_roundtrip_test(self):
        """Set and get global throttle settings"""
        testlib.post_succ(
            self.cluster, MCD_GLOBAL_ENDPOINT,
            data={
                "throttle_enabled": "true",
                "read_unit_size": "8192",
                "write_unit_size": "2048",
                "node_capacity": "10000",
            }, expected_code=202)
        r = testlib.get_succ(self.cluster, MCD_GLOBAL_ENDPOINT)
        settings = r.json()
        testlib.assert_eq(True, settings.get("throttle_enabled"))
        testlib.assert_eq(8192, settings.get("read_unit_size"))
        testlib.assert_eq(2048, settings.get("write_unit_size"))
        testlib.assert_eq(10000, settings.get("node_capacity"))
