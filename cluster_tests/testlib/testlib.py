# @author Couchbase <info@couchbase.com>
# @copyright 2020-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import atexit
from abc import ABC, abstractmethod
import requests
import string
import random
import time
import io
import sys
import contextlib
from traceback import format_exception_only
import traceback_with_variables as traceback

from testlib.node import Node

def support_colors():
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

config={'colors': support_colors(),
        'verbose': False,
        'screen_width': 80,
        'dry_run': False}


def try_reuse_cluster(requirements, cluster):
    # If we can use the existing cluster then we should
    if len(requirements.get_unmet_requirements(cluster)) == 0:
        return True, []

    # Attempt to satisfy the requirements with the existing cluster if
    # possible
    satisfiable, unsatisfied = requirements.is_satisfiable(cluster)
    if satisfiable:
        for requirement in unsatisfied:
            with no_output("make_met"):
                requirement.make_met(cluster)
        # We should not have unmet requirements at this point.
        # If we do, it is a bug in make_met() or in is_met()
        if len(unmet:=requirements.get_unmet_requirements(cluster)) > 0:
            raise RuntimeError(f'Internal error. Unmet requirements: {unmet}')
        return True, []
    return False, unsatisfied


def get_appropriate_cluster(cluster, auth, start_index, requirements,
                            tmp_cluster_dir, kill_nodes):
    if cluster is not None:
        reuse, _ = try_reuse_cluster(requirements, cluster)
        if reuse:
            return cluster

        # Teardown the old cluster
        cluster.teardown()
        # We no longer need to kill these nodes. A new atexit function will
        # be registered in requirements.create_cluster
        atexit.unregister(kill_nodes)

        start_index = cluster.start_index + len(cluster.processes)
        print()

    # Create a new cluster satisfying the requirements
    print(f"=== Starting cluster to satisfy requirements: {requirements}")
    cluster = requirements.create_cluster(auth, start_index,
                                          tmp_cluster_dir,
                                          kill_nodes)
    maybe_print("\n======================================="
                "=========================================\n")
    return cluster


def run_testset(testset_class, test_names, cluster, testset_name,
                intercept_output=True, seed=None):
    errors = []
    not_ran = []
    executed = 0
    print(f"\nStarting testset: {testset_name}...")

    testset_instance = testset_class(cluster)

    _, err = safe_test_function_call(testset_instance, 'setup', [],
                                     intercept_output=intercept_output,
                                     seed=seed)

    test_seed = apply_with_seed(random, 'randbytes', [16], seed)
    test_teardown_seed = apply_with_seed(random, 'randbytes', [16], test_seed)
    teardown_seed = apply_with_seed(random, 'randbytes', [16], test_teardown_seed)

    if err is not None:
        # If testset setup fails, all tests were not ran
        for not_ran_test in test_names:
            not_ran.append((not_ran_test,
                            "testset setup failed"))
        return 0, [err], not_ran

    try:
        for test in test_names:
            executed += 1
            _, err = safe_test_function_call(testset_instance, test,
                                             [], verbose=True,
                                             intercept_output=intercept_output,
                                             seed=test_seed)
            if err is not None:
                errors.append(err)

            _, err = safe_test_function_call(testset_instance, 'test_teardown',
                                             [],
                                             intercept_output=intercept_output,
                                             seed=test_teardown_seed)
            if err is not None:
                errors.append(err)
                # Don't try to run further tests as test_teardown failure will
                # likely cause additional test failures which are irrelevant
                for not_ran_test in test_names[executed:]:
                    not_ran.append((not_ran_test,
                                    "Earlier test_teardown failed"))
                break
    finally:
        _, err = safe_test_function_call(testset_instance, 'teardown',
                                         [],
                                         intercept_output=intercept_output,
                                         seed=teardown_seed)
        if err is not None:
            errors.append(err)

    return executed, errors, not_ran


def safe_test_function_call(testset, testfunction, args, verbose=False,
                            intercept_output=True, seed=None, dry_run=None):
    if dry_run is None:
        dry_run = config['dry_run']
    res = None
    error = None
    if hasattr(testset, '__name__'):
        testname = f"{testset.__name__}.{testfunction}"
    else:
        testname = f"{type(testset).__name__}.{testfunction}"

    report_call = call_reported(testname, verbose=verbose,
                                res_on_same_line=intercept_output)
    try:
        with no_output(testname, extra_context=report_call,
                       verbose=not intercept_output):
            if not dry_run:
                res = apply_with_seed(testset, testfunction, args, seed)
    except Exception as e:
        cscheme = None if config['colors'] else traceback.ColorSchemes.none
        traceback.print_exc(fmt=traceback.Format(color_scheme=cscheme),
                            file_=sys.stdout)
        error = (testname, e)
    return res, error


def apply_with_seed(obj, func, args, seed):
    try:
        rand_state = random.getstate()
        random.seed(seed)
        return getattr(obj, func)(*args)
    finally:
        random.setstate(rand_state)


def timedelta_str(start):
    delta_s = time.time() - start
    if delta_s > 10:
        return red(f" [{round(delta_s)}s]")
    if delta_s > 5:
        return red(f" [{delta_s:.1f}s]")
    elif delta_s > 1:
        return f" [{delta_s:.1f}s]"
    elif delta_s > 0.1:
        return f" [{delta_s:.2f}s]"
    else:
        return f""


def red(str):
    return maybe_color(str, 31)


def green(str):
    return maybe_color(str, 32)


def maybe_color(str, code):
    if config['colors']:
        return f"\033[{code}m{str}\033[0m"
    else:
        return str


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
    def setup(self):
        """
        Executed before any test in the testset.

        """
        raise NotImplementedError()

    @abstractmethod
    def teardown(self):
        """
        Executed when all tests are finished.

        """
        raise NotImplementedError()

    def test_teardown(self):
        """
        Executed when after each test finishes.

        """
        pass


def delete_config_key(cluster, key):
    return post_succ(cluster, '/diag/eval', data=f'ns_config:delete({key})')


def request(method, cluster_or_node, path, expected_code=None, **kwargs):
    if 'timeout' not in kwargs:
        kwargs['timeout'] = 60
    kwargs_with_auth = set_default_auth(cluster_or_node, **kwargs)
    if isinstance(cluster_or_node, Node):
        url = cluster_or_node.url + path
    else:
        url = cluster_or_node.connected_nodes[0].url + path
    print(f'sending {method} {url} {kwargs} (expected code {expected_code})')
    res = requests.request(method, url, **kwargs_with_auth)
    print(f'result: {res.status_code}')
    if expected_code is not None:
        assert_http_code(expected_code, res),
    return res


def put_succ(cluster_or_node, path, expected_code=200, **kwargs):
    return request('PUT', cluster_or_node, path, expected_code, **kwargs)


def patch_succ(cluster_or_node, path, expected_code=200, **kwargs):
    return request('PATCH', cluster_or_node, path, expected_code, **kwargs)


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


def delete_succ(cluster_or_node, path, expected_code=200, **kwargs):
    return request('DELETE', cluster_or_node, path, expected_code, **kwargs)


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
        cluster.delete_bucket(bucket['name'])


def get_otp_nodes(cluster):
    info = json_response(get(cluster, "/nodeStatuses"),
                         "/nodeStatuses response was not json")
    return {k: info[k]['otpNode'] for k in info}

def poll_for_condition(fun, sleep_time, attempts=None, timeout=None,
                       verbose=False, msg="poll for condition"):

    assert (attempts is not None) or (timeout is not None)
    assert sleep_time > 0, "non-positive sleep_time specified"
    start_time = time.time()
    sleep_time_str = f"{sleep_time:.2f}s"

    attempt_count = 0
    while (attempts is None) or (attempt_count < attempts):
        if timeout is not None:
            assert (time.time() - start_time) < timeout, \
                   f"{msg}: timed-out (timeout: {timeout}s)"
        if fun():
            maybe_print(f"Time taken for condition to complete: "
                        f"{time.time() - start_time: .2f}s", verbose=verbose)
            return
        maybe_print(f"Sleeping for {sleep_time_str}", verbose=verbose)
        time.sleep(sleep_time)
        attempt_count += 1
    assert False, f"{msg} didn't complete in: {attempts} attempts, " \
                  f"sleep_time: {sleep_time_str}"


def diag_eval(cluster, code):
    return post_succ(cluster, '/diag/eval', data=code)


@contextlib.contextmanager
def no_output(name, verbose=None, extra_context=contextlib.nullcontext()):
    """
    Executes context body with all the output redirected to a string.
    If something crashes, it prints that output, otherwise it ignores it.
    If verbose is true, it doesn't redirect anything.
    If extra_context is provided, the body is executed in that context, but the
    extra_context output is not redirected. The main purpose of
    the extra_context param, is to have an ability to print something (the
    result of execution) before this function starts dumping the redirected
    output (in case of a crash)
    """
    if verbose is None:
        verbose = config['verbose']

    if verbose:
        with extra_context:
            yield
        return

    f = io.StringIO()
    try:
        with extra_context:
            with contextlib.redirect_stdout(f):
                yield
    except Exception as e:
        output = f.getvalue()
        if len(output) > 0:
            extra_cr = '\n' if output[-1] != '\n' else ''
            print(
                f"================== {name} output begin =================\n"
                f"{output}{extra_cr}"
                f"=================== {name} output end ==================\n")

        raise e


@contextlib.contextmanager
def call_reported(name, succ_str="ok", fail_str="failed", verbose=False,
                  res_on_same_line=True):
    """
    Executes context body and reports result in the following format:
      <name>...           <succ_str> [<time_taken>]
    or
      <name>...           <fail_str> [<time_taken>]
    if context body throws exception.
    If verbose is false, prints only unsuccessful result in slightly different
    format.
    If res_on_same_line is false, puts result on the next line.
    """

    start = time.time()
    try:
        str_to_print = f"  {name}... " + ('\n' if not res_on_same_line else '')
        width_taken = len(str_to_print)
        if verbose:
            print(str_to_print, end='', flush=True)
        yield
        if verbose:
            if res_on_same_line:
                res = right_aligned(succ_str, taken=width_taken)
            else:
                res = succ_str
            print(green(res) + timedelta_str(start))
    except Exception as e:
        short_exception = red('\n'.join(format_exception_only(type(e), e))
                              .strip('\n'))
        if verbose:
            if res_on_same_line:
                res = right_aligned(fail_str, taken=width_taken)
            else:
                res = fail_str
            print(red(res) + timedelta_str(start))
            print(f'    {short_exception}')
        else:
            print(red(f"{name} {fail_str} ({short_exception})"))
        raise e


def right_aligned(s, taken=0, width=config['screen_width']):
    corrected_width = max(0, width - taken)
    return f'{s: >{corrected_width}}'


def no_output_decorator(f):
    def wrapped_f(*args, **kwargs):
        with no_output(f.__name__):
            return f(*args, **kwargs)
    return wrapped_f


def maybe_print(s, verbose=None, print_fun=print):
    if verbose is None:
        verbose = config['verbose']
    if verbose:
        print_fun(s)
