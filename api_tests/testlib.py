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
from abc import ABC, abstractmethod
import traceback
from collections import namedtuple
import requests


Cluster = namedtuple("Cluster", ['urls', 'processes', 'auth'])
ClusterRequirements = namedtuple("ClusterRequirements", ['num_nodes'])


def run_testset(testset_class, test_names, available_clusters):
    errors = []
    executed = 0
    print(f"\nStarting testset: {testset_class.__name__}...")

    (requirements, err) = \
        safe_test_function_call(testset_class, 'requirements', [])

    if err is not None:
        return (0, [err])

    clusters = [c for c in available_clusters
                if cluster_matches_requirements(c, requirements)]

    if len(clusters) == 0:
        msg = "Failed to find a cluster that fits test "\
              f"requirements ({requirements})"
        print(msg)
        return (0, [('preparation', msg)])

    testset_instance = testset_class()

    _, err = safe_test_function_call(testset_instance, 'setup', [clusters[0]])

    if err is not None:
        return (0, [err])

    try:
        for test in test_names:
            executed += 1
            _, err = safe_test_function_call(testset_instance, test,
                                             [clusters[0]], verbose=True)
            if err is not None:
                errors.append(err)
    finally:
        _, err = safe_test_function_call(testset_instance, 'teardown',
                                         [clusters[0]])
        if err is not None:
            errors.append(err)

    return (executed, errors)


def safe_test_function_call(testset, testfunction, args, verbose=False):
    res = None
    error = None
    testname = ""
    if hasattr(testset, '__name__'):
        testname = f"{testset.__name__}.{testfunction}"
    else:
        testname = f"{type(testset).__name__}.{testfunction}"
    if verbose: print(f"  {testname}... ", end = '')
    try:
        res = getattr(testset, testfunction)(*args)
        if verbose: print("succ")
    except Exception as e:
        if verbose:
            print(f"failed ({e})")
        else:
            print(f"  {testname} failed ({e})")
        traceback.print_exc()
        error = (testname, e)
    return (res, error)


def cluster_matches_requirements(cluster, requirements):
    return requirements.num_nodes == len(cluster.urls)


class BaseTestSet(ABC):
    @staticmethod
    @abstractmethod
    def requirements():
        """
        Executed before any test in the testset.
        Returns requirements for cluster needed for testset

        """
        raise NotImplementedError()

    @abstractmethod
    def setup(self, cluster):
        """
        Executed before any test in the testset.

        """
        raise NotImplementedError()

    @abstractmethod
    def teardown(self, cluster):
        """
        Executed when all tests are finished.

        """
        raise NotImplementedError()
