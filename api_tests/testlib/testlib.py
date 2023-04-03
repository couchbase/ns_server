# @author Couchbase <info@couchbase.com>
# @copyright 2020-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
from abc import ABC, abstractmethod
import traceback
from collections import namedtuple
import requests
import string
import random

from testlib.node import Node

ClusterRequirements = namedtuple("ClusterRequirements",
                                 ['num_nodes', 'min_memsize', 'serverless',
                                  'num_connected'],
                                 defaults=[1, 256, None, None])

def get_appropriate_cluster(available_clusters, testset_class):
    (requirements, err) = \
        safe_test_function_call(testset_class, 'requirements', [])

    if err is not None:
        return err

    clusters = [c for c in available_clusters
                if cluster_matches_requirements(c, requirements)]

    if len(clusters) == 0:
        msg = "Failed to find a cluster that fits test requirements,\n" \
              f"    {requirements}"
        return msg
    return clusters[0]

def run_testset(testset_class, test_names, cluster):
    errors = []
    executed = 0
    print(f"\nStarting testset: {testset_class.__name__}...")

    testset_instance = testset_class(cluster)

    _, err = safe_test_function_call(testset_instance, 'setup', [cluster])

    if err is not None:
        return (0, [err])

    try:
        for test in test_names:
            executed += 1
            _, err = safe_test_function_call(testset_instance, test,
                                             [cluster], verbose=True)
            if err is not None:
                errors.append(err)

            _, err = safe_test_function_call(testset_instance, 'test_teardown',
                                             [cluster])
            if err is not None:
                errors.append(err)
    finally:
        _, err = safe_test_function_call(testset_instance, 'teardown',
                                         [cluster])
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
    if verbose: print(f"  {testname}... ", end='')
    try:
        res = getattr(testset, testfunction)(*args)
        if verbose: print("\033[32m passed \033[0m")
    except Exception as e:
        if verbose:
            print(f"\033[31m failed ({e}) \033[0m")
        else:
            print(f"\033[31m  {testname} failed ({e}) \033[0m")
        traceback.print_exc()
        error = (testname, e)
    return (res, error)


def cluster_matches_requirements(cluster, requirements):
    return (requirements.num_nodes == len(cluster.nodes) and
            requirements.min_memsize <= cluster.memsize and
            (requirements.serverless is None or
             requirements.serverless == cluster.is_serverless) and
            (requirements.num_connected is None or
             requirements.num_connected == len(cluster.connected_nodes)))


class BaseTestSet(ABC):
    def __init__(self, cluster):
        self.cluster = cluster

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

    def test_teardown(self, cluster):
        """
        Executed when after each test finishes.

        """
        pass


def delete_config_key(cluster, key):
    return post_succ(cluster, '/diag/eval', data=f'ns_config:delete({key})')


def request(method, cluster_or_node, path, expected_code=None, **kwargs):
    kwargs_with_auth = set_default_auth(cluster_or_node, **kwargs)
    if isinstance(cluster_or_node, Node):
        url = cluster_or_node.url + path
    else:
        url = cluster_or_node.nodes[0].url + path
    res = requests.request(method, url, **kwargs_with_auth)
    if expected_code is not None:
        assert_http_code(expected_code, res),
    return res


def put_succ(cluster_or_node, path, expected_code=200, **kwargs):
    return request('PUT', cluster_or_node, path, expected_code, **kwargs)


def post_succ(cluster_or_node, path, expected_code=200, **kwargs):
    return request('POST', cluster_or_node, path, expected_code, **kwargs)


def post_fail(cluster_or_node, path, expected_code, **kwargs):
    return request('POST', cluster_or_node, path, expected_code, **kwargs)


def post(cluster_or_node, path, **kwargs):
    return request('POST', cluster_or_node, path, None, **kwargs)


def get_succ(cluster_or_node, path, expected_code=200, **kwargs):
    return request('GET', cluster_or_node, path, expected_code, **kwargs)


def get_fail(cluster_or_node, path, expected_code, **kwargs):
    return request('GET', cluster_or_node, path, expected_code, **kwargs)


def get(cluster_or_node, path, **kwargs):
    return request('GET', cluster_or_node, path, None, **kwargs)


def ensure_deleted(cluster, path, **kwargs):
    res = delete(cluster, path, **kwargs)
    code = res.status_code
    assert code == 200 or code == 404, format_http_error(res, [200, 404])
    return res


def delete(cluster_or_node, path, **kwargs):
    return request('DELETE', cluster_or_node, path, None, **kwargs)


def set_default_auth(cluster_or_node, **kwargs):
    if 'auth' not in kwargs:
        new_kwargs = kwargs.copy()
        new_kwargs.update({'auth': cluster_or_node.auth})
        return new_kwargs
    return kwargs


def assert_http_code(expected_code, res):
    code = res.status_code
    assert code == expected_code, format_http_error(res, [expected_code])


def format_http_error(res, expected_codes):
    expected_codes_str = " or ".join([str(c) for c in expected_codes])
    return f"{res.request.method} {res.url} " \
           f"returned {res.status_code} {res.reason} " \
           f"(expected {expected_codes_str})" \
           f", response body: {res.text}"


def assert_json_key(expected_key, json, context):
    assert expected_key in json.keys(), \
        f"({context}) '{expected_key}' missing in json: {json}"
    return json[expected_key]


def random_str(n):
    return ''.join(random.choices(string.ascii_lowercase +
                                  string.digits, k=n))


def json_response(response, error):
    try:
        return response.json()
    except requests.exceptions.JSONDecodeError:
        assert False, error


def delete_all_buckets(cluster, **kwargs):
    buckets = get_succ(cluster, "/pools/default/buckets", **kwargs)
    for bucket in buckets.json():
        name = bucket['name']
        ensure_deleted(cluster, f"/pools/default/buckets/{name}")
