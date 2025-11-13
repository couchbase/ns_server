# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

# This module is used to create a cluster running an older release to
# be used in mixed-version and upgrade tests.

import importlib.util
import inspect
import os
from urllib.error import URLError

import testlib


def get_node_urls(nodes):
    return [node.url for node in nodes]


def filter_to_supported_params(func, args):
    """Filter args to the params accepted by func, to avoid a TypeError when
    the old version lacks newer optional kwargs. Returns args unchanged if
    func accepts **kwargs. Any dropped keys are printed."""
    sig = inspect.signature(func)
    if any(p.kind == inspect.Parameter.VAR_KEYWORD
           for p in sig.parameters.values()):
        return args
    filtered = {k: v for k, v in args.items() if k in sig.parameters}
    ignored = sorted(args.keys() - filtered.keys())
    if ignored:
        print(f"Ignoring args not supported by legacy {func.__name__}(): "
              f"{ignored}")
    return filtered


def get_legacy_cluster_run_lib():
    path = testlib.config['older-version-path']
    cluster_run_lib_path = f"{path}/pylib/cluster_run_lib.py"
    if not os.path.exists(cluster_run_lib_path):
        raise RuntimeError(
            f"older-version-path {cluster_run_lib_path} not found")

    spec = importlib.util.spec_from_file_location("legacy_cluster_run_lib",
                                                  cluster_run_lib_path)
    legacy_cluster_run_lib = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy_cluster_run_lib)
    return legacy_cluster_run_lib


def build_cluster(address, auth, cluster_index, start_args, connect,
                  connect_args, disconnected_args, get_cluster, node_init,
                  add_cluster_to_auto_kill, kill_nodes, get_terminal_attrs):
    legacy_cluster_run_lib = get_legacy_cluster_run_lib()
    # 'mixed_version' is only a flag used to select this legacy build path;
    # it isn't a start_cluster()/connect() parameter, and it must not end up
    # stored on the resulting Cluster's start_args, or a later
    # restart_node()/restart_all_nodes() call would pass it on to
    # cluster_run_lib.start_cluster() and fail.
    start_args.pop('mixed_version', None)
    port = legacy_cluster_run_lib.base_api_port + start_args['start_index']
    num_nodes = start_args['num_nodes']
    nodes = [testlib.Node(host=address,
                          port=port + i,
                          auth=auth)
             for i in range(num_nodes)]
    urls = get_node_urls(nodes)

    processes = []
    try:
        print(f"Starting cluster with start args:\n{start_args}")
        # Filter into a copy -- start_args is reused below (and by the
        # caller) to build the new-version nodes' start args, which must
        # keep every key.
        legacy_start_args = filter_to_supported_params(
            legacy_cluster_run_lib.start_cluster, start_args)
        processes = legacy_cluster_run_lib.start_cluster(**legacy_start_args)

        if connect:
            try:
                print(f"Connecting cluster with connect args:\n{connect_args}")
                connect_args = filter_to_supported_params(
                    legacy_cluster_run_lib.connect, connect_args)
                error = legacy_cluster_run_lib.connect(**connect_args)
                if error:
                    raise RuntimeError(
                        f"Failed to connect node(s). Status: {error}")
                print(f"Initialising disconnected nodes with args:\n"
                      f"{disconnected_args}")
                node_init(auth, **disconnected_args)
            except URLError as e:
                raise RuntimeError(f"Failed to connect node(s). {e}\n"
                                   f"Perhaps a node has already been started "
                                   f"at {address}:{port}?\n")

        cluster = get_cluster(cluster_index, port, auth, processes, nodes,
                              start_args)
        add_cluster_to_auto_kill(cluster_index, processes, urls)
        return cluster, urls
    except Exception:
        if processes:
            kill_nodes(processes, urls, get_terminal_attrs())
        raise
