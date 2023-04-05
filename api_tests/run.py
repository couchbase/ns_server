#!/usr/bin/env python3
#
# @author Couchbase <info@couchbase.com>
# @copyright 2020-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import os
import sys
import getopt
import shutil
import inspect
import atexit
import requests
import glob

scriptdir = os.path.dirname(os.path.realpath(__file__))
pylib = os.path.join(scriptdir, "..", "pylib")
sys.path.append(pylib)

import cluster_run_lib
import testlib
import authn_tests
import auto_failover_test
import sample_buckets
import ldap_tests
import tasks_test
import saml_tests
import bucket_deletion_test

tmp_cluster_dir = os.path.join(scriptdir, "test_cluster_data")

USAGE_STRING = """
Usage: {program_name}
    [--cluster | -c <address>:<port>]
        Specify already started cluster to connect to.
    [--user | -u <admin>]
        Username to be used when connecting to an existing cluster.
        Default: Administrator. Only used with --cluster | -c
    [--password | -p <admin_password>]
        Password to be used when connecting to an existing cluster.
        Default: asdasd. Only used with --cluster | -c
    [--num-nodes | -n <num_nodes>]
        Number of nodes available for an existing cluster. Use when not all
        nodes are already connected, for tests that need this configuration.
        When unspecified, num_nodes is assumed to be equal to the number of
        connected nodes. Only used with --cluster | -c
    [--tests | -t <test_spec>[, <test_spec> ...]]
        <test_spec> := <test_class>[.test_name]
        Start only specified tests
    [--keep-tmp-dirs | -k]
        Keep any test_cluster_data dirs after tests finish, even if they pass
    [--help]
        Show this help
"""

def usage():
    print(USAGE_STRING.format(program_name=sys.argv[0]))

def bad_args_exit(msg):
    print(f"\033[31m{msg}\033[0m")
    usage()
    sys.exit(2)

def error_exit(msg):
    print(f"\033[31m{msg}\033[0m")
    sys.exit(2)


def remove_temp_cluster_directories():
    for dir in glob.glob(tmp_cluster_dir + "*"):
        print(f"Removing cluster dir {dir}...")
        shutil.rmtree(dir)


def kill_nodes(clusters, terminal_attrs):
    for c in clusters:
        cluster_run_lib.kill_nodes(c.processes, terminal_attrs,
                                   [node.url for node in c.nodes])


def kill_nodes_and_remove_dirs(clusters, terminal_attrs):
    kill_nodes(clusters, terminal_attrs)
    remove_temp_cluster_directories()


# If anything goes wrong after starting the clusters, we want to kill the
# nodes, otherwise we end up with processes hanging around
def setup_safe_exit(clusters, remove_dirs=False):
    terminal_attrs = None
    try:
        import termios
        terminal_attrs = termios.tcgetattr(sys.stdin)
    except Exception:
        pass

    if remove_dirs:
        # When we want to remove the directories, we should register with a
        # different function name, so that we can safely unregister the original
        # atexit function after we've registered the new function
        atexit.register(kill_nodes_and_remove_dirs, clusters, terminal_attrs)
        atexit.unregister(kill_nodes)
    else:
        atexit.register(kill_nodes, clusters, terminal_attrs)


def main():
    try:
        optlist, args = getopt.gnu_getopt(sys.argv[1:], "hkc:u:p:n:t:",
                                          ["help", "keep-tmp-dirs", "cluster=",
                                           "user=", "password=", "num-nodes=",
                                           "tests="])
    except getopt.GetoptError as err:
        bad_args_exit(str(err))

    use_existing_server = False
    username = 'Administrator'
    password = 'asdasd'
    num_nodes = None
    address = '127.0.0.1'
    start_port = cluster_run_lib.base_api_port
    start_index = 0
    tests = None
    keep_tmp_dirs = False

    for o, a in optlist:
        if o in ('--cluster', '-c'):
            tokens = a.split(':')
            if len(tokens) != 2:
                bad_args_exit(f"Invalid format. Should be {o} <address>:<port>")
            address = tokens[0]
            start_port = int(tokens[1])
            start_index = start_port - cluster_run_lib.base_api_port
            use_existing_server = True
        elif o in ('--user', '-u'):
            if not use_existing_server:
                bad_args_exit(f"{o} is only supported with --cluster | -c")
            username = a
        elif o in ('--password', '-p'):
            if not use_existing_server:
                bad_args_exit(f"{o} is only supported with --cluster | -c")
            password = a
        elif o in ('--num-nodes', '-n'):
            if not use_existing_server:
                bad_args_exit(f"{o} is only supported with --cluster | -c")
            num_nodes = int(a)
        elif o in ('--tests', '-t'):
            tests = []
            for tokens in [t.strip().split(".") for t in a.split(",")]:
                if len(tokens) == 1:
                    tests.append((tokens[0], '*'))
                elif len(tokens) == 2:
                    tests.append((tokens[0], tokens[1]))
        elif o in ('--keep-tmp-dirs', '-k'):
            keep_tmp_dirs = True
        elif o in ('--help', '-h'):
            usage()
            exit(0)
        else:
            assert False, f"unhandled options: {o}"

    discovered_tests = discover_testsets()

    errors = {}
    not_ran = []
    # Remove any testsets that didn't correctly specify requirements
    for discovered_test in discovered_tests:
        (name, _, _, configuration) = discovered_test
        if not isinstance(configuration, testlib.ClusterRequirements):
            reason = configuration
            not_ran.append((name, reason))
            discovered_tests.remove(discovered_test)

    if len(not_ran) > 0:
        msg = "Some testsets did not correctly specify requirements:\n"
        for (name, reason) in not_ran:
            msg += f"{name} - {reason}\n"
        error_exit(msg)
    print(f"Discovered testsets: {[c for c, _, _, _ in discovered_tests]}")

    if tests is None:
        testsets_to_run = discovered_tests
    else:
        testsets_to_run = find_tests(tests, discovered_tests)

    if use_existing_server:
        # Get provided cluster
        clusters = [get_existing_cluster(address, start_port,
                                         (username, password), num_nodes)]
        print(f"Discovered cluster: {clusters[0]}")
    else:
        remove_temp_cluster_directories()

        print("Starting required clusters...")
        clusters = get_required_clusters(testsets_to_run,
                                         (username, password),
                                         start_index)
        setup_safe_exit(clusters)
        print(f"Started clusters:")
        for cluster in clusters:
            print(f"  - {cluster}")
        print("\n======================================="
              "=========================================\n" )

    executed = 0
    for class_name, testset, test_names, configuration in testsets_to_run:
        cluster = testlib.get_appropriate_cluster(clusters, configuration)
        testset_name = f"{class_name}/{configuration}"
        if isinstance(cluster, testlib.Cluster):
            res = testlib.run_testset(testset, test_names, cluster, testset_name)
            executed += res[0]
            testset_errors = res[1]
            if len(testset_errors) > 0:
                errors[testset_name] = testset_errors
        else:
            reason = cluster
            not_ran.append((testset_name, reason))

    error_num = sum([len(errors[name]) for name in errors])
    errors_str = f"{error_num} error{'s' if error_num != 1 else ''}"
    if error_num == 0:
        colour = "\033[32m"
    else:
        colour = "\033[31m"
    print("\n======================================="
          "=========================================\n"
          f"{colour}Tests finished ({executed} executed, {errors_str})\033[0m")

    for name in errors:
        print(f"In {name}:")
        for testres in errors[name]:
            print(f"  {testres[0]} failed: {testres[1]}")
    print()

    for name, reason in not_ran:
        print(f"Couldn't run {name}:\n"
              f"  {reason}")
    print()

    if len(errors) > 0:
        error_exit("Tests finished with errors")
    else:
        # Kill any created nodes and possibly delete directories as we don't
        # need to keep around data from successful tests
        if not keep_tmp_dirs:
            setup_safe_exit(clusters, True)


def find_tests(test_names, discovered_list):
    results = {}
    discovered_dict = {n: (cl, t, cf) for n, cl, t, cf in discovered_list}
    for class_name, test_name in test_names:
        assert class_name in discovered_dict, \
            f"Testset {class_name} is not found. "\
            f"Available testsets: {list(discovered_dict.keys())}"
        testset, tests, configuration = discovered_dict[class_name]
        if test_name == '*':
            results[class_name] = (testset, tests, configuration)
        else:
            assert test_name in tests, \
                f"Test {test_name} is not found in {class_name}. "\
                f"Available tests: {tests})"

            if class_name in results:
                testlist = results[class_name][1]
                testlist.append(test_name)
                results[class_name] = (results[class_name][0], testlist,
                                       configuration)
            else:
                results[class_name] = (testset, [test_name], configuration)

    return [(k, results[k][0], results[k][1], results[k][2]) for k in results]


def discover_testsets():
    testsets = []

    for m in sys.modules.keys():
        if not hasattr(sys.modules[m], '__file__'):
            continue
        if sys.modules[m].__file__ is None:
            continue
        if scriptdir != os.path.dirname(sys.modules[m].__file__):
            continue
        for name, testset in inspect.getmembers(sys.modules[m], inspect.isclass):
            if testset == testlib.BaseTestSet:
                continue
            if issubclass(testset, testlib.BaseTestSet):
                tests = [m for m in dir(testset) if m.endswith('_test')]
                if len(tests) > 0:
                    requirements, err = testlib.safe_test_function_call(
                        testset, 'requirements', [])
                    if err is None:
                        testsets.append((name, testset, tests, requirements))
                    else:
                        testsets.append((name, testset, tests, err))

    return testsets


def get_existing_cluster(address, start_port, auth, num_nodes):
    url = f"http://{address}:{start_port}"

    # Check that node is online
    pools_default = f"{url}/pools/default"
    try:
        response = requests.get(pools_default, auth=auth)
    except requests.exceptions.ConnectionError as e:
        error_exit(f"Failed to connect to {pools_default}\n"
                   f"{e}")
    if response.status_code != 200:
        error_exit(f"Failed to connect to {pools_default} "
                   f"({response.status_code})\n"
                   f"{response.text}")
    # Retrieve the number of nodes
    nodes_found = len(response.json().get("nodes", []))
    if nodes_found == 0:
        error_exit(f"Failed to retrieve nodes from {pools_default}")

    if num_nodes is None:
        # Assume that there are no nodes that are not already connected
        num_nodes = nodes_found

    return testlib.cluster.get_cluster(address, start_port, auth, [], num_nodes,
                                       nodes_found)


def get_required_clusters(testsets, auth, start_index):
    clusters = []
    for (name, testset, tests, requirements) in testsets:
        satisfied = False
        for cluster in clusters:
            if requirements.is_met(cluster):
                satisfied = True
        if not satisfied:
            clusters.append(requirements.create_cluster(auth, start_index,
                                                        tmp_cluster_dir))
            start_index += len(clusters[-1].processes)
    return clusters


if __name__ == '__main__':
    main()
