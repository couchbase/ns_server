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
import requests
from urllib.error import URLError

import testlib

scriptdir = os.path.dirname(os.path.realpath(__file__))
pylib = os.path.join(scriptdir, "..", "pylib")
sys.path.append(pylib)

import cluster_run_lib


def build_cluster(auth, start_args, connect_args):
    processes = cluster_run_lib.start_cluster(**start_args)
    # We use the raw ip address instead of 'localhost', as it isn't accepted by
    # the addNode or doJoinCluster endpoints
    address = "127.0.0.1"
    port = cluster_run_lib.base_api_port + start_args['start_index']
    try:
        error = cluster_run_lib.connect(**connect_args)
        if error:
            print(f"Failed to connect node(s). Status: {error}")
    except URLError as e:
        print(f"Failed to connect node(s). {e}\n"
              f"Perhaps a node has already been started at "
              f"{address}:{port}?\n")
    return get_cluster(address, port, auth, processes, start_args['num_nodes'],
                       connect_args['num_nodes'])


def get_cluster(address, start_port, auth, processes, num_nodes, num_connected):
    urls = []
    nodes = []
    connected_nodes = []
    for i in range(num_nodes):
        node = testlib.Node(host=address,
                            port=start_port + i,
                            auth=auth)
        # Check that node is connected to the cluster.
        if i < num_connected:
            pools_default = f"{node.url}/pools/default"
            try:
                response = requests.get(pools_default, auth=auth)
                connected_nodes.append(node)
            except requests.exceptions.ConnectionError as e:
                sys.exit(f"Failed to connect to {pools_default}\n"
                         f"{e}")
            if response.status_code != 200:
                sys.exit(f"Failed to connect to {pools_default} "
                         f"({response.status_code})\n"
                         f"{response.text}")
        urls.append(node.url)
        nodes.append(node)

    try:
        memsize = response.json()["memoryQuota"]
    except NameError as e:
        sys.exit(f"Response has not been defined, perhaps no nodes haves "
                 f"connected. {e}")

    return Cluster(nodes=nodes,
                   connected_nodes=connected_nodes,
                   processes=processes,
                   auth=auth,
                   memsize=memsize)


class Cluster:
    def __init__(self, nodes, connected_nodes, processes, auth, memsize):
        self.nodes = nodes
        self.connected_nodes = connected_nodes
        self.processes = processes
        self.auth = auth
        self.memsize = memsize

        def get_bool(code):
            return testlib.post_succ(self, "/diag/eval",
                                     data=code).text == "true"

        self.is_enterprise = get_bool("cluster_compat_mode:is_enterprise().")
        self.is_71 = get_bool("cluster_compat_mode:is_cluster_71().")
        self.is_elixir = get_bool("cluster_compat_mode:is_cluster_elixir().")
        self.is_serverless = get_bool("config_profile:is_serverless().")
        self.is_dev_preview = get_bool("cluster_compat_mode:"
                                       "is_developer_preview().")

        def diag_eval(code):
            return testlib.post_succ(self, "/diag/eval",
                                     data=code).text.strip('\"')

        self.data_path = diag_eval("path_config:component_path(data).")

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
