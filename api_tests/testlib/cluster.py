# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import os
import sys

import testlib

scriptdir = os.path.dirname(os.path.realpath(__file__))
pylib = os.path.join(scriptdir, "..", "pylib")
sys.path.append(pylib)

import cluster_run_lib


class Cluster:
    def __init__(self, nodes, connected_nodes, processes, auth, memsize,
                 is_enterprise, is_71, is_elixir, is_serverless, is_dev_preview,
                 data_path):
        self.nodes = nodes
        self.connected_nodes = connected_nodes
        self.processes = processes
        self.auth = auth
        self.memsize = memsize
        self.is_enterprise = is_enterprise
        self.is_71 = is_71
        self.is_elixir = is_elixir
        self.is_serverless = is_serverless
        self.is_dev_preview = is_dev_preview
        self.data_path = data_path

    def __str__(self):
        return self.__dict__.__str__()

    # Check every 0.5s until there is no rebalance running or 600s have passed
    def wait_for_rebalance(self, timeout_s=600, interval_s=0.5, verbose=False):
        cluster_run_lib.wait_for_rebalance(self.nodes[0].url, timeout_s,
                                           interval_s, verbose)

    # Rebalance the cluster, and possibly eject nodes at the same time.
    # Can optionally wait for the rebalance to finish
    def rebalance(self, ejected_nodes=None, wait=True, timeout_s=600,
                  verbose=False):
        # We have to use the otpNode names instead of the node ips, so we fetch
        # these from /nodeStatuses
        info = testlib.json_response(testlib.get(self, "/nodeStatuses"),
                                     "/nodeStatuses response was not json")
        otp_nodes = {k: info[k]['otpNode'] for k in info}

        # It is unlikely that known_nodes should ever need to be manually
        # generated, as the list of nodes retrieved here is the only accepted
        # value
        known_nodes_string = ",".join(otp_nodes.values())

        if ejected_nodes is None:
            ejected_nodes_string = ""
        else:
            # Get the otp nodes to eject by checking the port of each entry in
            # the /nodeStatuses result, and comparing against the port of each
            # node to be ejected
            ejected_nodes_string = ",".join(otp_nodes[node.hostname]
                                            for node in ejected_nodes)

        data = {'knownNodes': known_nodes_string,
                'ejectedNodes': ejected_nodes_string}

        if verbose:
            print(f"Starting rebalance with {data}")

        testlib.post_succ(self, "/controller/rebalance", data=data)

        # Optionally wait for the rebalance to complete
        if wait:
            self.wait_for_rebalance(timeout_s=timeout_s, verbose=verbose)

    # Add new_node to the cluster, and optionally perform a rebalance
    def add_node(self, new_node, services="kv", do_rebalance=False,
                 verbose=False):
        # Can only add nodes with the https address, which requires the 1900X
        # port
        cluster_member_port = 10000 + new_node.port
        data = {"user": self.auth[0],
                "password": self.auth[1],
                "hostname": f"https://{new_node.host}:{cluster_member_port}",
                "services": services}
        if verbose:
            print(f"Adding node {data}")
        r = testlib.post_succ(self, f"/controller/addNode", data=data)

        if do_rebalance:
            self.rebalance(verbose=verbose)
            self.wait_for_rebalance(verbose=verbose)
        return r

    # Wait for all associated nodes be responsive, each with a 60s timeout.
    # May be needed after removing a node, if it needs to be immediately added
    # back in to the cluster.
    def wait_nodes_up(self, timeout_s=60, verbose=False):
        cluster_run_lib.wait_nodes_up(
            timeout_s=timeout_s,
            node_urls=[node.url for node in self.nodes],
            verbose=verbose)
