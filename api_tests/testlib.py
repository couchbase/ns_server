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


Cluster = namedtuple("Cluster", ['urls', 'processes', 'auth', 'memsize',
                                 'is_enterprise', 'is_71', 'is_elixir',
                                 'is_serverless', 'is_dev_preview', 'data_path'])
ClusterRequirements = namedtuple("ClusterRequirements",
                                 ['num_nodes', 'min_memsize', 'serverless'],
                                 defaults=[1, 256, None])

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

    testset_instance = testset_class()

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
    return (requirements.num_nodes == len(cluster.urls) and
            requirements.min_memsize <= cluster.memsize and
            (requirements.serverless is None or
             requirements.serverless == cluster.is_serverless))


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

    def test_teardown(self, cluster):
        """
        Executed when after each test finishes.

        """
        pass


def delete_config_key(cluster, key):
    return post_succ(cluster, '/diag/eval', data=f'ns_config:delete({key})')


def put_succ(cluster, path, **kwargs):
    kwargs_with_auth = set_default_auth(cluster, **kwargs)
    url = cluster.urls[0] + path
    res = requests.put(url, **kwargs_with_auth)
    assert_http_code(200, res),
    return res


def post_succ(cluster, path, **kwargs):
    res = post(cluster, path, **kwargs)
    assert_http_code(200, res)
    return res


def post_fail(cluster, path, expected_code, **kwargs):
    res = post(cluster, path, **kwargs)
    assert_http_code(expected_code, res),
    return res


def post(cluster, path, **kwargs):
    kwargs_with_auth = set_default_auth(cluster, **kwargs)
    url = cluster.urls[0] + path
    return requests.post(url, **kwargs_with_auth)


def get_succ(cluster, path, **kwargs):
    res = get(cluster, path, **kwargs)
    assert_http_code(200, res),
    return res


def get_fail(cluster, path, expected_code, **kwargs):
    res = get(cluster, path, **kwargs)
    assert_http_code(expected_code, res),
    return res


def get(cluster, path, **kwargs):
    kwargs_with_auth = set_default_auth(cluster, **kwargs)
    url = cluster.urls[0] + path
    return requests.get(url, **kwargs_with_auth)


def ensure_deleted(cluster, path, **kwargs):
    res = delete(cluster, path, **kwargs)
    code = res.status_code
    assert code == 200 or code == 404, format_http_error(res, [200, 404])
    return res


def delete(cluster, path, **kwargs):
    kwargs_with_auth = set_default_auth(cluster, **kwargs)
    url = cluster.urls[0] + path
    return requests.delete(url, **kwargs_with_auth)


def set_default_auth(cluster, **kwargs):
    if 'auth' not in kwargs:
        new_kwargs = kwargs.copy()
        new_kwargs.update({'auth': cluster.auth})
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
