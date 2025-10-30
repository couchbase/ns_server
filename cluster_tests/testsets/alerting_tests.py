# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import testlib
from datetime import datetime
import os
import re
from cryptography import x509
import urllib.parse

import sys
sys.path.append(testlib.get_pylib_dir())
import cluster_run_lib

class AlertTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=2, num_connected=1,
                                           afamily="ipv4")

    def setup(self):
        testlib.diag_eval(self.cluster, "menelaus_web_alerts_srv:reset().")
        limits = testlib.get_succ(self.cluster, "/settings/alerts/limits")\
            .json()
        self.prev_cert_expiration = limits["certExpirationDays"]

        # Set alert check interval to 1s
        testlib.diag_eval(self.cluster,
                          "ns_config:set({timeout,{menelaus_web_alerts_srv,"
                          "sample_rate}}, 1000)")
        testlib.diag_eval(self.cluster,
                          "menelaus_web_alerts_srv ! check_alerts")

    def teardown(self):
        testlib.diag_eval(self.cluster, "menelaus_web_alerts_srv:reset().")
        testlib.post_succ(self.cluster, "/settings/alerts/limits",
                          data={"certExpirationDays":
                                str(self.prev_cert_expiration)})

        # Set alert check interval back to default 60s
        testlib.diag_eval(self.cluster,
                          "ns_config:delete({timeout,{menelaus_web_alerts_srv,"
                          "sample_rate}})")

    def cert_about_to_expire_alert_test(self):
        node_data_dir = self.cluster.connected_nodes[0].data_path()
        certs_dir = os.path.join(node_data_dir, "config", "certs")
        cert_path = os.path.join(certs_dir, "chain.pem")
        client_cert_path = os.path.join(certs_dir, "client_chain.pem")
        expiration1 = get_expiration_for_cert(cert_path)
        expiration2 = get_expiration_for_cert(client_cert_path)
        max_expiration = max(expiration1, expiration2)

        testlib.post_succ(self.cluster, "/settings/alerts/limits",
                          data={"certExpirationDays": str(max_expiration)})

        def check_alert():
            r = testlib.get_succ(self.cluster, "/pools/default").json()
            alerts = r["alerts"]
            if len(alerts) < 2:
                print(f"Alert check failed, expected >= 2 alerts, got {alerts}")
                return False

            regex = r"^Server certificate for node .+ will expire at .+$"

            def is_expected(x): return re.match(regex, x["msg"]) is not None
            has_node_alert = any(map(is_expected, alerts))

            if not has_node_alert:
                print(f"Alert check failed, expected {regex}, got {alerts}")
                return False

            regex = r"^Client certificate on node .+ will expire at .+$"

            def is_expected(x): return re.match(regex, x["msg"]) is not None
            has_client_alert = any(map(is_expected, alerts))

            if not has_client_alert:
                print(f"Alert check failed, expected {regex}, got {alerts}")
                return False

            return True

        testlib.poll_for_condition(check_alert, sleep_time=1, timeout=120,
                                   verbose=True,
                                   msg="wait for cert expiration alert")
    def to_node(self):
        return self.cluster._nodes[1]

    def from_node(self):
        return self.cluster._nodes[0]

    def xdcr_replications_deleted_alert_test(self):
        def check_xdcr_up():
            r = testlib.get(self.cluster, "/pools/default/replications")
            return r.status_code == 200

        # If we do not wait, we will get an `econnrefused` error from goxdcr
        testlib.poll_for_condition(check_xdcr_up, sleep_time=1, timeout=30)
        resp = testlib.get_succ(self.cluster,
                                "/pools/default/replications").json()
        assert len(resp) == 0
        protocol = "ipv4"
        hostname = self.to_node().host
        testlib.post_succ(self.to_node(), "/nodeInit",
                          data={"afamily": protocol,
                                "hostname": hostname})
        data = {"afamily": "ipv4",
                "nodeEncryption": "off",
                "memoryQuota": 256,
                "port": "SAME",
                "username": "Administrator",
                "password": "asdasd",
                "services": "kv"}
        testlib.post_succ(self.to_node(), "/clusterInit", data=data)

        def check_node_ready():
            r = testlib.get(self.to_node(), "/pools/default")
            return r.status_code == 200

        testlib.poll_for_condition(check_node_ready, sleep_time=5, timeout=300,
                                   msg="wait for to_node to be ready")

        data = {"name": "A",
                "ramQuotaMB": 128}
        testlib.post_succ(self.from_node(), "/pools/default/buckets",
                          expected_code=202, data=data)
        testlib.post_succ(self.to_node(), "/pools/default/buckets",
                          expected_code=202, data=data)

        cluster_run_lib.wait_for_rebalance(
            f"http://{self.from_node().host}:{self.from_node().port}")
        cluster_run_lib.wait_for_rebalance(
            f"http://{self.to_node().host}:{self.to_node().port}")

        testlib.post_succ(self.cluster, "/pools/default/remoteClusters",
                          data={"name": "n_1",
                                "hostname":
                                f"{self.to_node().host}:{self.to_node().port}",
                                "port": self.to_node().port,
                                "username": "Administrator",
                                "password": "asdasd"}).json()

        def check_remote_cluster():
            diag_expr = "chronicle_kv:get(kv, {bucket, \"A\", last_balanced_vbmap})."
            r = testlib.diag_eval(self.to_node(), diag_expr)
            return r.text.startswith("{ok,")

        testlib.poll_for_condition(check_remote_cluster, sleep_time=1,
                                   timeout=120)
        testlib.post_succ(self.cluster, "/controller/createReplication",
                          data={"fromBucket": "A",
                                "replicationType": "continuous",
                                "toBucket": "A",
                                "toCluster": "n_1"}).json()

        def check_replication_created():
            r = testlib.get_succ(self.cluster,
                                 "/pools/default/replications").json()
            return len(r) >= 1

        testlib.poll_for_condition(check_replication_created, sleep_time=1,
                                   timeout=120)

        # Need to ensure that we've recorded the creation of the replication.
        def check_replication_recorded():
            statname = "xdcr_number_of_replications_total"
            response = testlib.get_succ(
                self.from_node(),
                f"/_prometheus/api/v1/query?query={statname}").json()
            value = response["data"]["result"]
            if len(value) == 0:
                return False
            repl_count = int(float(value[0]["value"][1]))
            return repl_count >= 1

        testlib.poll_for_condition(check_replication_recorded, sleep_time=1,
                                   timeout=60)
        alerts_json = testlib.get_succ(self.cluster, "/pools/default").json()
        for alert in alerts_json["alerts"]:
            assert "XDCR replication deleted on node" not in alert["msg"]

        replications = testlib.get_succ(self.cluster,
                                        "/pools/default/replications").json()
        for repl in replications:
            repl_id: str = repl["id"]
            repl_id = urllib.parse.quote(repl_id, safe="")
            resp = testlib.delete_succ(
                self.cluster,
                f"/controller/cancelXDCR/{repl_id}").json()

        def check_alert():
            r = testlib.get_succ(self.cluster, "/pools/default").json()
            for alert in r["alerts"]:
                if "XDCR replication deleted on node" in alert["msg"]:
                    return True
            return False

        testlib.poll_for_condition(check_alert, sleep_time=1, timeout=60,
                                   msg="waiting for XDCR replication deleted alert")
        testlib.post_succ(self.to_node(), "/controller/hardResetNode", data={})

        def check_node_reset():
            r = testlib.get(self.to_node(), "/pools/default")
            return r.status_code != 200

        testlib.poll_for_condition(check_node_reset, sleep_time=5,
                                   timeout=300)


def get_expiration_for_cert(cert_path):
    print(f"Extracting expiration for {cert_path}")
    with open(cert_path, "rb") as f:
        pem = f.read()
    cert = x509.load_pem_x509_certificate(pem)
    expire_datetime = cert.not_valid_after
    print(f"expire_datetime: {expire_datetime}")
    now_datetime = datetime.utcnow()
    print(f"now: {now_datetime}")
    assert expire_datetime > now_datetime
    will_expire_in = (expire_datetime - now_datetime).days + 1
    print(f"cert will expire in {will_expire_in} days")
    return will_expire_in
