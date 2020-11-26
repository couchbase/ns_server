#!/usr/bin/env python3
#
# @author Couchbase <info@couchbase.com>
# @copyright 2020 Couchbase, Inc.
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

import os
import sys
import getopt
import time
import shutil
import inspect
import atexit

scriptdir = os.path.dirname(os.path.realpath(__file__))
pylib = os.path.join(scriptdir, "..", "pylib")
sys.path.append(pylib)

import cluster_run_lib
import testlib
import dummy_test

tmp_cluster_dir = os.path.join(scriptdir, "test_cluster_data")

USAGE_STRING = """
Usage: {program_name}
    [--start-server | -s]
        Start its own couchbase-server for tests or will try connect to
        127.0.0.1:9000 by default. Note that default port can be changed by
        --start-index option.
    [--start-index <N>]
        Index of existing cluster_run node to connect to. Default: 0
    [--user | -u <admin>]
        Username to be used when connecting to an existing cluster.
        Mutually exclusive to --start-server. Default: Administrator
    [--password | -p <admin_password>]
        Password to be used when connecting to an existing cluster.
        Mutually exclusive to --start-server. Default: asdasd
    [--help]
        Show this help
"""

def usage():
    print(USAGE_STRING.format(program_name=sys.argv[0]))

def error_exit(msg):
    print(msg)
    usage()
    sys.exit(2)

def main():
    try:
        optlist, args = getopt.gnu_getopt(sys.argv[1:], "hsu:p:",
                                          ["help", "start-server",
                                           "user=", "password=",
                                           "start-index="])
    except getopt.GetoptError as err:
        error_exit(str(err))

    start_server = False
    username = 'Administrator'
    password = 'asdasd'
    start_index = 0

    for o, a in optlist:
        if o in ('--start-server', '-s'):
            start_server = True
        elif o in ('--user', '-u'):
            if start_server == True:
                error_exit(f"{o} is not supported when test cluster is started")
            username = a
        elif o in ('--password', '-p'):
            if start_server == True:
                error_exit(f"{o} is not supported when test cluster is started")
            password = a
        elif o == '--start-index':
            start_index = int(a)
        elif o in ('--help', '-h'):
            usage()
            exit(0)
        else:
            assert False, f"unhandled options: {o}"

    clusters = []
    processes = []

    if start_server:
        if os.path.isdir(tmp_cluster_dir):
            print(f"Removing cluster dir {tmp_cluster_dir}...")
            shutil.rmtree(tmp_cluster_dir)
        print("Starting couchbase server...")
        processes = cluster_run_lib.start_cluster(num_nodes=1,
                                                  start_index=start_index,
                                                  root_dir=tmp_cluster_dir,
                                                  wait_for_start=True,
                                                  nooutput=True)
        cluster_run_lib.connect(num_nodes=1,
                                start_index=start_index,
                                do_rebalance=False)

    url = f"http://127.0.0.1:{cluster_run_lib.base_api_port + start_index}"
    clusters.append(testlib.Cluster(urls=[url],
                                    processes=processes,
                                    auth=(username, password)))

    print(f"Available cluster configurations: {clusters}")

    testsets_to_run = discover_testsets()

    print(f"Discovered testsets: {[c.__name__ for c in testsets_to_run]}")

    errors = {}
    executed = 0
    for testset in testsets_to_run:
        res = testlib.run_testset(testset, clusters)
        executed += res[0]
        testset_errors = res[1]
        if len(testset_errors) > 0:
            errors[testset.__name__] = testset_errors

    error_num = sum([len(errors[name]) for name in errors])
    errors_str = "1 error" if error_num == 1 else f"{error_num} errors"

    print("\n======================================="\
          "=========================================\n"\
          f"Tests finished ({executed} executed, {errors_str})")

    for name in errors:
        print(f"In {name}:")
        for testres in errors[name]:
            print(f"  {testres[0]} failed: {testres[1]}")
    print()

    terminal_attrs = None

    try:
        import termios
        terminal_attrs = termios.tcgetattr(sys.stdin)
    except Exception:
        pass

    def kill_nodes():
        for c in clusters:
            cluster_run_lib.kill_nodes(c.processes, terminal_attrs)

    atexit.register(kill_nodes)

    if len(errors) > 0:
        sys.exit("Tests finished with errors")


def discover_testsets():
    testsets = []

    for m in sys.modules.keys():
        if not hasattr(sys.modules[m], '__file__'):
            continue
        if sys.modules[m].__file__ is None:
            continue
        if scriptdir != os.path.dirname(sys.modules[m].__file__):
            continue
        for c in inspect.getmembers(sys.modules[m], inspect.isclass):
            if c[1] == testlib.BaseTestSet:
                continue
            if issubclass(c[1], testlib.BaseTestSet):
                testsets.append(c[1])

    return testsets

if __name__ == '__main__':
    main()
