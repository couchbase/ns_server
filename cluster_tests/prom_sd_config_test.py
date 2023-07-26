# @author Couchbase <info@couchbase.com>
# @copyright 2023 Couchbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This tests the /prometheus_sd_config endpoint which is intended to be
# used to configure prometheus (MB-55047) to get scrape targets on the
# fly instead of hard coding them in a file.
#
# The API accepts query parameters:
#
#   type={json|yaml}
#   disposition={inline|attachment}
#   port={secure|insecure}
#   network={default|external}
#
# The first of the options is the default. When disposition is "attachment"
# the extension for filename will be based on "type".

import testlib
import json
import yaml
import time


class PromSdConfigTest(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=3)

    def setup(self, cluster):
        self.alt_addr_url = "/node/controller/setupAlternateAddresses/external"

    def teardown(self, cluster):
        for node in cluster.nodes:
            testlib.delete(node, self.alt_addr_url)

    def build_hostname(self, node_num):
        return f"{node_num}.{node_num}.{node_num}.{node_num}"

    def build_portnum(self, node_num, secure=False):
        Secure = "1" if secure else ""
        return f"{Secure}{node_num}{node_num}{node_num}{node_num}"

    # Setup alternate addresses and mgmt ports
    def setup_alt_addresses(self, cluster):
        node_num = 1

        for node in cluster.nodes:
            alt_hostname = self.build_hostname(node_num)
            mgmt_port = self.build_portnum(node_num)
            mgmtSSL_port = self.build_portnum(node_num, True)
            print(f"Setting alternate address for node {alt_hostname} "
                  f"port {mgmt_port} SSL port {mgmtSSL_port}")

            node_num += 1
            testlib.put_succ(node, self.alt_addr_url,
                             data={"hostname": f"{alt_hostname}",
                                   "mgmt": f"{mgmt_port}",
                                   "mgmtSSL": f"{mgmtSSL_port}"})

    # Verify the alternate addresses and kv ports
    def verify_alt_addresses(self, cluster):
        retries = 60
        while retries > 0:
            if self.verify_alt_addresses_inner(cluster):
                return
            time.sleep(0.5)
            retries -= 1
        raise RuntimeError("alternate addresses did not come up")

    def verify_alt_addresses_inner(self, cluster):
        r = testlib.get_succ(cluster, "/pools/default/nodeServices")
        rj = r.json()
        nodesExt = rj['nodesExt']
        node_num = 1
        for node in nodesExt:
            if 'alternateAddresses' not in node:
                return False
            altaddr = node['alternateAddresses']
            external = altaddr['external']
            hostname = external['hostname']
            ports = external['ports']
            port = ports['mgmt']
            portSSL = ports['mgmtSSL']
            assert (hostname == self.build_hostname(node_num))
            assert (port == int(self.build_portnum(node_num)))
            assert (portSSL == int(self.build_portnum(node_num, True)))
            node_num += 1
        return True

    def build_url(self, ret_type, disposition, port, network):
        assert (ret_type in ["json", "yaml"])
        assert (disposition in ["inline", "attachment"])
        assert (port in ["secure", "insecure"])
        assert (network in ["default", "external"])

        # Save args for validating the response
        self.ret_type = ret_type
        self.disposition = disposition
        self.port = port
        self.network = network

        url = f"/prometheus_sd_config?type={ret_type}&" \
              f"disposition={disposition}&port={port}&network={network}"

        print(f"\nTesting url: {url}")
        return url

    def get_sd_config(self, cluster, ret_type="json", disposition="inline",
                      port="secure", network="default"):
        url = self.build_url(ret_type, disposition, port, network)
        return testlib.get_succ(cluster, url)

    def verify_sd_config(self, cluster):
        self.validate_response(cluster,
                               self.get_sd_config(cluster, disposition="attachment"))
        self.validate_response(cluster,
                               self.get_sd_config(cluster, ret_type="yaml",
                                                  port="insecure"))
        self.validate_response(cluster,
                               self.get_sd_config(cluster, ret_type="yaml",
                                                  port="insecure",
                                                  network="external"))
        self.validate_response(cluster,
                               self.get_sd_config(cluster, ret_type="yaml",
                                                  port="insecure",
                                                  network="external",
                                                  disposition="attachment"))

    def validate_response(self, cluster, resp):
        if self.ret_type == "json":
            r = resp.json()
        else:  # yaml
            yaml_resp = yaml.safe_load(resp.text)
            r = json.loads(json.dumps(yaml_resp))
        targets = r[0]["targets"]

        if self.disposition == "attachment":
            content = resp.headers['content-disposition']
            expected = f'attachment; ' \
                f'filename="couchbase_sd_config_.{self.ret_type}"'
            assert (content == expected)

        node_num = 1
        for node in cluster.nodes:
            if self.network == "default":
                host = node.host
                port = node.port
                if self.port == "secure":
                    port = f"1{port}"
            else:  # external
                host = self.build_hostname(node_num)
                port = self.build_portnum(node_num, self.port == "secure")
            expected_hostname = f"{host}:{port}"

            assert (expected_hostname in targets)
            targets.remove(expected_hostname)
            node_num += 1

        assert (len(targets) == 0)

    def negative_tests(self, cluster):
        # Failures occur when alternate addresses/ports are not configured
        url = self.build_url("json", "inline", "insecure", "external")
        testlib.get_fail(cluster, url, 400)
        url = self.build_url("json", "inline", "secure", "external")
        testlib.get_fail(cluster, url, 400)

    def sd_config_test(self, cluster):
        # Some negative tests before alternate addresses are specified
        self.negative_tests(cluster)

        # Setup alternate addresses/ports
        self.setup_alt_addresses(cluster)
        self.verify_alt_addresses(cluster)
        # Positive tests
        self.verify_sd_config(cluster)
