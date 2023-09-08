# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import atexit
import os
import sys
import time
import requests
from urllib.error import URLError

import testlib

scriptdir = os.path.dirname(os.path.realpath(__file__))
pylib = os.path.join(scriptdir, "..", "pylib")
sys.path.append(pylib)

import cluster_run_lib


# We attempt to fetch terminal_attrs when killing nodes, to override any changes
# made by the nodes
def get_terminal_attrs():
    try:
        import termios
        return termios.tcgetattr(sys.stdin)
    except Exception:
        return None


def get_node_urls(nodes):
    return [node.url for node in nodes]


def build_cluster(auth, cluster_index, start_args, connect_args, kill_nodes):
    # We use the raw ip address instead of 'localhost', as it isn't accepted by
    # the addNode or doJoinCluster endpoints
    # IPV6 uses [::1] instead of 127.0.0.1
    address = "::1" if connect_args['protocol'] == "ipv6" else "127.0.0.1"
    port = cluster_run_lib.base_api_port + start_args['start_index']
    num_nodes = start_args['num_nodes']
    nodes = [testlib.Node(host=address,
                          port=port + i,
                          auth=auth)
             for i in range(num_nodes)]
    urls = get_node_urls(nodes)

    # Start the cluster
    print(f"Starting cluster with start args:\n{start_args}")
    processes = cluster_run_lib.start_cluster(**start_args)

    try:
        # Connect the nodes
        print(f"Connecting cluster with connect args:\n{connect_args}")
        error = cluster_run_lib.connect(**connect_args)
        if error:
            sys.exit(f"Failed to connect node(s). Status: {error}")
    except URLError as e:
        sys.exit(f"Failed to connect node(s). {e}\n"
                 f"Perhaps a node has already been started at "
                 f"{address}:{port}?\n")
    finally:
        # If anything goes wrong after starting the clusters, we want to kill
        # the nodes, otherwise we end up with processes hanging around
        atexit.register(kill_nodes, processes, urls, get_terminal_attrs())
    return get_cluster(cluster_index, port, auth, processes, nodes,
                       connect_args['num_nodes'])


def get_cluster(cluster_index, start_port, auth, processes, nodes, num_connected):
    connected_nodes = []
    for i, node in enumerate(nodes):
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

    try:
        memsize = response.json()["memoryQuota"]
    except NameError as e:
        sys.exit(f"Response has not been defined, perhaps no nodes haves "
                 f"connected. {e}")

    cluster = Cluster(nodes=nodes,
                      connected_nodes=connected_nodes,
                      first_node_index=start_port - cluster_run_lib.base_api_port,
                      processes=processes,
                      auth=auth,
                      memsize=memsize,
                      index=cluster_index)
    print(f"Successfully connected to cluster: {cluster}")
    return cluster


class Cluster:
    def __init__(self, nodes, connected_nodes, first_node_index, processes, auth,
                 memsize, index):
        self.nodes = nodes
        self.connected_nodes = connected_nodes
        self.first_node_index = first_node_index
        self.index = index
        self.processes = processes
        self.auth = auth
        self.memsize = memsize

        def get_bool(code):
            return testlib.post_succ(self, "/diag/eval",
                                     data=code).text == "true"

        self.is_enterprise = get_bool("cluster_compat_mode:is_enterprise().")
        self.is_trinity = get_bool("cluster_compat_mode:is_cluster_trinity().")
        self.is_serverless = get_bool("config_profile:is_serverless().")
        self.is_provisioned = get_bool("config_profile:is_provisioned()")
        self.is_dev_preview = get_bool("cluster_compat_mode:"
                                       "is_developer_preview().")


    def __str__(self):
        return f'Cluster#{self.index}(' + \
               ','.join([str(n) for n in self.connected_nodes]) + ')'

    def __repr__(self):
        return self.__dict__.__repr__()

    # Kill all associated nodes to avoid competing for resources with the active
    # cluster being tested against
    def teardown(self):
        with testlib.no_output("kill nodes"):
            cluster_run_lib.kill_nodes(self.processes, get_terminal_attrs(),
                                       urls=get_node_urls(self.nodes))

    # Check every 0.5s until there is no rebalance running or 600s have passed
    def wait_for_rebalance(self, timeout_s=600, interval_s=0.5, verbose=False):
        return cluster_run_lib.wait_for_rebalance(self.connected_nodes[0].url,
                                                  timeout_s, interval_s,
                                                  verbose)

    # Rebalance the cluster, and possibly eject nodes at the same time.
    # Can optionally wait for the rebalance to finish.
    # Note, when using expected_error or initial_expected_error, the TestSet
    # is responsible for ensuring that if there is an unexpected rebalance, the
    # cluster is still in an equivalent state after teardown to its state before
    # the TestSet was executed on the cluster.
    def rebalance(self, ejected_nodes=None, wait=True, timeout_s=600,
                  verbose=False, expected_error=None, initial_code=200,
                  initial_expected_error=None):
        # We have to use the otpNode names instead of the node ips.
        otp_nodes = testlib.get_otp_nodes(self)

        # Filter out ejected_nodes which don't have an otp_node (meaning they
        # are not currently part of the cluster).
        if ejected_nodes is not None:
            for node in ejected_nodes:
                if not node.hostname() in otp_nodes.keys():
                    ejected_nodes.remove(node)

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
            ejected_nodes_string = ",".join(otp_nodes[node.hostname()]
                                            for node in ejected_nodes)

        data = {'knownNodes': known_nodes_string,
                'ejectedNodes': ejected_nodes_string}

        if verbose:
            print(f"Starting rebalance with {data}")

        if initial_expected_error is None:
            testlib.post_succ(self, "/controller/rebalance", data=data,
                              expected_code=initial_code)

            # Update connected_nodes with any changes so that wait_for_rebalance
            # doesn't query a node that is being removed
            if ejected_nodes is not None:
                for node in ejected_nodes:
                    self.connected_nodes.remove(node)

            # Optionally wait for the rebalance to complete
            if wait:
                error = self.wait_for_rebalance(timeout_s=timeout_s,
                                                verbose=verbose)
                assert error is expected_error, \
                    f"Expected final rebalance status: {expected_error}\n" \
                    f"Found: {error}"

                expected_nodes = [node.hostname()
                                  for node in self.connected_nodes]

                def nodes_are_expected():
                    resp = testlib.get_succ(self, "/pools/default")
                    nodes = [n["hostname"] for n in resp.json()["nodes"]]
                    print(f"Got nodes: {nodes}")
                    return sorted(nodes) == sorted(expected_nodes)

                # Wait until the cluster's nodes are as expected
                testlib.poll_for_condition(
                    nodes_are_expected, sleep_time=1, attempts=30,
                    msg=f"wait for nodes in /pools/default to be consistent")

                # Rebalance has finished, but the ejected nodes can still
                # (a) think they are part of the cluster
                # (b) be starting web server after leaving
                # Here we wait for such nodes to leave the cluster and
                # start web server.
                if ejected_nodes is not None:
                    def ejected_node_is_up(node):
                        try:
                            resp = testlib.get(node, '/pools/default')
                            return 404 == resp.status_code and \
                                   '"unknown pool"' == resp.text
                        except Exception as e:
                            print(f'got exception: {e}')
                            return False

                    for n in ejected_nodes:
                        testlib.poll_for_condition(
                            lambda: ejected_node_is_up(node),
                            sleep_time=1, timeout=60,
                            msg=f'wait for ejected node {n} to be up')

        else:
            r = testlib.post_fail(self, "/controller/rebalance", data=data,
                                  expected_code=initial_code)
            assert r.text == initial_expected_error, \
                f"Expected rebalance error: {initial_expected_error}\n" \
                f"Found: {r.text}"

    # Add new_node to the cluster, and optionally perform a rebalance
    def add_node(self, new_node, services="kv", do_rebalance=False,
                 verbose=False, expected_code=200, expected_error=None):
        # Can only add nodes with the https address, which requires the 1900X
        # port
        data = {"user": self.auth[0],
                "password": self.auth[1],
                "hostname": new_node.https_url(),
                "services": services}
        if verbose:
            print(f"Adding node {data}")
        r = testlib.post_succ(self, f"/controller/addNode", data=data,
                              expected_code=expected_code)

        if expected_code==200:
            # Update connected_nodes with the newly added node
            self.connected_nodes.append(new_node)

            if do_rebalance:
                self.rebalance(verbose=verbose, expected_error=expected_error)
        return r

    def do_join_cluster(self, new_node, services="kv", do_rebalance=False,
                        verbose=False, expected_code=200):
        data = {"user": self.auth[0],
                "password": self.auth[1],
                "hostname": self.connected_nodes[0].https_url(),
                "services": services}

        if verbose:
            print(f"doJoinCluster with {data}")
        r = testlib.post_succ(
            path="/node/controller/doJoinCluster",
            cluster_or_node=new_node,
            data=data, expected_code=expected_code)

        if expected_code==200:
            # Update connected_nodes with the newly added node
            self.connected_nodes.append(new_node)

            if do_rebalance:
                self.rebalance(wait=True, verbose=verbose)
        return r

    def failover_node(self, victim_node, graceful=True, allow_unsafe=False,
                      verbose=False, victim_otp_node=None, expected_code=200):
        if victim_otp_node is None:
            # We have to use the otpNode names instead of the node ips.
            otp_nodes = testlib.get_otp_nodes(self)
            victim_otp_node = otp_nodes[victim_node.hostname()]

        data = {"user": self.auth[0],
                "password": self.auth[1],
                "otpNode": f"{victim_otp_node}",
                "allowUnsafe": "true" if allow_unsafe else "false"}
        if verbose:
            print(f"Failing over node {data}")
        failover_type = "startGracefulFailover" if graceful else "startFailover"
        non_victim_nodes = [x for x in self.connected_nodes if x != victim_node]
        if expected_code == 200:
            r = testlib.post_succ(non_victim_nodes[0],
                                  f"/controller/{failover_type}",
                                  data=data)
            self.connected_nodes.remove(victim_node)

            # Wait for the failover to complete
            self.wait_for_rebalance(verbose=verbose)
        else:
            r = testlib.post_fail(non_victim_nodes[0],
                                  f"/controller/{failover_type}",
                                  data=data,
                                  expected_code=expected_code)
        return r

    def recover_node(self, node, recovery_type="full", do_rebalance=False,
                     verbose=False):
        assert recovery_type in ["full", "delta"]
        otp_nodes = testlib.get_otp_nodes(self)
        if node.hostname() in otp_nodes:
            otp_node = otp_nodes[node.hostname()]
        else:
            raise RuntimeError(f"Failed to find {node.hostname()} in otp_nodes")

        data = {"user": self.auth[0],
                "password": self.auth[1],
                "otpNode": f"{otp_node}",
                "recoveryType": recovery_type}
        if verbose:
            print(f"Recoverying {node.hostname()} with type {recovery_type}")
        r = testlib.post_succ(self, f"/controller/setRecoveryType",
                              data=data)
        self.connected_nodes.append(node)
        if do_rebalance:
            self.rebalance(wait=True, verbose=verbose)
        return r

    # Wait for all associated nodes be responsive, each with a 60s timeout.
    # This is specifically important for nodes that are not connected to the
    # cluster, in the case that they need to be immediately added back in to the
    # cluster, because these nodes will not be responsive immediately after
    # they are removed from the cluster.
    def wait_nodes_up(self, timeout_s=60, verbose=False):
        cluster_run_lib.wait_nodes_up(
            timeout_s=timeout_s,
            node_urls=get_node_urls(self.nodes),
            verbose=verbose)

    def create_bucket(self, data, verbose=False, expected_code=202):
        self.wait_for_rebalance(verbose=verbose)
        return testlib.post_succ(self, "/pools/default/buckets",
                                 expected_code=expected_code, data=data)

    def update_bucket(self, data, verbose=False, expected_code=200):
        self.wait_for_rebalance(verbose=verbose)
        bucket_name = data['name']
        return testlib.post_succ(self, f"/pools/default/buckets/{bucket_name}",
                                 data=data, expected_code=expected_code)

    def delete_bucket(self, name, verbose=False):
        self.wait_for_rebalance(verbose=verbose)
        return testlib.ensure_deleted(self, f"/pools/default/buckets/{name}")

    def get_orchestrator_node(self, node=None):
        cluster_or_node = self if node is None else node
        resp = testlib.get_succ(cluster_or_node,
                                "/pools/default/terseClusterInfo")
        orchestrator = resp.json()['orchestrator']
        resp = testlib.get_succ(cluster_or_node, "/pools/nodes").json()
        nodes = resp['nodes']
        orchestrator_hostname = ""
        is_serviceless = False
        for i in range(len(resp["nodes"])):
            if nodes[i]['otpNode'] == orchestrator:
                assert orchestrator_hostname == ""
                orchestrator_hostname = nodes[i]['hostname']
                is_serviceless = (nodes[i]['services'] == [])
        return orchestrator_hostname, is_serviceless

    # Wait until one of the nodes has been selected orchestrator. This
    # handles windows (e.g. node removal) where this might not be the case.
    # It is also used in unsafe failover to wait until the orchestrator has
    # transitioned to the desired node (orch_node). Nodes other than orch_node
    # may not be reachable when orch_node is specified.
    def wait_for_orchestrator(self, orch_node=None):
        retries = 60
        while retries > 0:
            orchestrator_hostname, _ = self.get_orchestrator_node(orch_node)
            if orchestrator_hostname != "":
                for node in self.nodes:
                    if orch_node is not None and node != orch_node:
                        continue
                    if node.hostname() == orchestrator_hostname:
                        return node
            time.sleep(0.5)
            retries -= 1

        raise RuntimeError("orchestrator node not found")

    def toggle_n2n_encryption(self, enable=True):
        """
        Helper function to enable/disable node to node encryption for all nodes
        in cluster.
        Note: It doesn't change nodes in self.nodes that are not members of
        the cluster
        :param self: Cluster object to send requests to
        :param enable: Whether node to node encryption should be enabled.
        """
        # Need to disable autoFailover before other settings can change
        r = testlib.get_succ(self, '/settings/autoFailover').json()
        autofailover_enabled = r['enabled']
        autofailover_timeout = r['timeout']
        if autofailover_enabled:
            testlib.post_succ(self, "/settings/autoFailover",
                              data={"enabled": "false"})

        for node in self.connected_nodes:
            # Create an external listener
            testlib.post_succ(node, "/node/controller/enableExternalListener",
                              data={"nodeEncryption": "on"
                                    if enable else "off"})

        for node in self.connected_nodes:
            # Change the node-to-node encryption settings
            testlib.post_succ(node, "/node/controller/setupNetConfig",
                              data={"nodeEncryption": "on"
                                    if enable else "off"})

        for node in self.connected_nodes:
            # Disable any unused listeners
            testlib.post_succ(node,
                              "/node/controller/disableUnusedExternalListeners")

        if autofailover_enabled:
            # Re-enable autoFailover.
            testlib.post_succ(self, "/settings/autoFailover",
                              data={"enabled": "true",
                                    "timeout": autofailover_timeout})
