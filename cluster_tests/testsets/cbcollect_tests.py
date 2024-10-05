# @author Couchbase <info@couchbase.com>
# @copyright 2024-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import os
import shutil
import zipfile
import re
from pathlib import Path
import testlib
from testlib.util import Service
from testlib import ClusterRequirements
from testsets.secret_management_tests import post_es_config, reset_es_config, \
                                             change_password
from testsets.native_encryption_tests import set_cfg_encryption
import datetime
import subprocess

FAKE_LOG_FILE = "analytics_debug.log"
regex_unredacted = re.compile("<ud>(?![a-f0-9]{40}</ud>)")

class CbcollectTest(testlib.BaseTestSet):
    @staticmethod
    def requirements():
        return [ClusterRequirements(edition="Enterprise")]

    def setup(self):
        node = self.cluster.connected_nodes[0]
        self.zip_dir = os.path.join(node.tmp_path(), "temp-zip")
        os.mkdir(self.zip_dir, mode=0o777)

    def teardown(self):
        # Not removing zip_dir on purpose.
        # It will be removed automatically because it is located in
        # test_cluster_data-*. At the same time having dumps unremoved is very
        # practical in case of test failure.
        pass

    def test_teardown(self):
        set_cfg_encryption(self.cluster, 'disabled', -1)
        for n in self.cluster.connected_nodes:
            reset_es_config(n)
            change_password(n, password='')

    def log_redaction_test(self):
        node = self.cluster.connected_nodes[0]

        shutil.copyfile(Path(testlib.get_resources_dir()) / "fixtures" /
                        FAKE_LOG_FILE,
                        Path(node.logs_path()) / FAKE_LOG_FILE)

        zip_filename = Path(self.zip_dir) / 'log_redaction_test_dump'
        task_regexp = f'couchbase logs \\({FAKE_LOG_FILE}\\)'

        # cbcollect creates two zips, one is redacted and the other one is not
        run_cbcollect(node, zip_filename, redaction_level="partial",
                      task_regexp=task_regexp)

        # verify that the unredacted zip actually contains unredacted data
        with zipfile.ZipFile(f'{zip_filename}.zip', mode="r") as z:
            file_to_check = cbcollect_filename(z, f'ns_server.{FAKE_LOG_FILE}')
            assert_file_has_undedacted_data(z, file_to_check)

        # verify that the redacted zip doesn't contain redacted data
        with zipfile.ZipFile(f'{zip_filename}-redacted.zip', mode="r") as z:
            file_to_check = cbcollect_filename(z, f'ns_server.{FAKE_LOG_FILE}')
            assert_file_is_redacted(z, file_to_check)

    def encrypted_cfg_master_password_via_script_test(self):
        node = self.cluster.connected_nodes[0]
        resourcedir = os.path.join(testlib.get_resources_dir(),
                                   'secrets_management')
        script_path = os.path.join(resourcedir, "getpass.sh")
        post_es_config(node, {'keyStorageType': 'file',
                              'keyEncrypted': 'true',
                              'passwordSource': 'script',
                              'passwordCmd': script_path})

        set_cfg_encryption(node, 'encryption_service', -1)

        zip_filename = Path(self.zip_dir) / 'encrypted_config_test_dump'
        collect_config_and_chronicle(node, zip_filename)

    def encrypted_cfg_master_password_via_env_test(self):
        node = self.cluster.connected_nodes[0]
        password = change_password(node)
        set_cfg_encryption(node, 'encryption_service', -1)

        zip_filename = Path(self.zip_dir) / 'encrypted_config_test_dump1'
        collect_config_and_chronicle(node, zip_filename,
                                     env_master_password=password)

    def encrypted_cfg_master_password_via_stdin_test(self):
        node = self.cluster.connected_nodes[0]
        password = change_password(node)
        set_cfg_encryption(node, 'encryption_service', -1)

        zip_filename = Path(self.zip_dir) / 'encrypted_config_test_dump2'
        collect_config_and_chronicle(node, zip_filename,
                                     stdin_master_password=password)

    def cbcollect_api_test(self):
        node = self.cluster.connected_nodes[0]
        password = change_password(node)
        set_cfg_encryption(node, 'encryption_service', -1)
        tasks = ['Couchbase config', 'Chronicle dump', 'Chronicle logs']
        task_regexp = '|'.join(tasks) + '|cbcollect_info'

        utcnow = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        otp_node = node.otp_node()
        testlib.post_succ(node, '/controller/startLogsCollection',
                          data = {'nodes': otp_node,
                                  'taskRegexp': task_regexp})

        def get_collected_file():
            r = testlib.get_succ(node, '/pools/default/tasks').json()
            print(f'got tasks: {r}')
            for t in r:
                if t['type'] == 'clusterLogsCollection':
                    if t['node'] != otp_node:
                        return False
                    if t['ts'] < utcnow:
                        return False
                    if t['status'] != 'completed':
                        return False
                    print(f'SUCC: {t["perNode"]}')
                    assert t["perNode"][otp_node]['status'] == 'collected', \
                           f'log collection failed: {t}'

                    return t['perNode'][otp_node]['path']
            return False

        file = testlib.poll_for_condition(get_collected_file, sleep_time=1,
                                          attempts=60, verbose=True)

        with zipfile.ZipFile(file, mode="r") as z:
            log = cbcollect_filename(z, 'cbcollect_info.log')
            assert_tasks_are_successfull(z, log, tasks)

    def incorrect_password_test(self):
        node = self.cluster.connected_nodes[0]
        set_cfg_encryption(node, 'encryption_service', -1)
        password = testlib.random_str(8)

        # Passing incorrect password while the master password is not set:
        assert_cbcollect_returns_incorrect_password(
            node, self.zip_dir, stdin_master_password=password + '_wrong')

        change_password(node, password=password)

        # Not passing password at all:
        assert_cbcollect_returns_incorrect_password(node, self.zip_dir)

        # Passing incorrect password:
        assert_cbcollect_returns_incorrect_password(
            node, self.zip_dir, stdin_master_password=password + '_wrong')


def run_cbcollect(node, path_to_zip, redaction_level=None, task_regexp=None,
                  env_master_password=None, stdin_master_password=None,
                  expected_exit_code=0):
    print(f'Starting cbcollect at node {node} to file: {path_to_zip}...')
    initargs = os.path.join(node.data_path(), "initargs")
    args = [testlib.get_utility_path('cbcollect_info'),
            "--initargs", initargs, str(path_to_zip)]
    env = {"PATH": os.environ['PATH'],
           "PYTHONPATH": testlib.get_pylib_dir()}

    if env_master_password is not None:
        env["CB_MASTER_PASSWORD"] = env_master_password

    if redaction_level is not None:
        args.extend(["--log-redaction-level", redaction_level])

    if task_regexp is not None:
        args.extend(["--task-regexp", task_regexp])

    if stdin_master_password is not None:
        args.append("--stdin-password")

    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=env)

    out, err = p.communicate(input=stdin_master_password, timeout=120)

    print(f'cbcollect return {p.returncode}')

    assert p.returncode == expected_exit_code, \
           f'cbcollect returned {p.returncode}: {err}'

    return (out, err)


def collect_config_and_chronicle(node, zip_filename, **kwargs):
    tasks = ['Couchbase config', 'Chronicle dump', 'Chronicle logs']
    task_regexp = '|'.join(tasks) + '|cbcollect_info'

    run_cbcollect(node, zip_filename, task_regexp=task_regexp, **kwargs)

    with zipfile.ZipFile(f'{zip_filename}.zip', mode="r") as z:
        log = cbcollect_filename(z, 'cbcollect_info.log')
        assert_tasks_are_successfull(z, log, tasks)


def cbcollect_dirname(zip_obj):
    names = zip_obj.namelist()

    p = names[0]

    # calculating the most left component which is the main cbcollect dump dir
    dir_name = None
    while p:
        p, dir_name = os.path.split(p)

    return dir_name


def cbcollect_filename(zip_obj, name):
    return os.path.join(cbcollect_dirname(zip_obj), name)


def assert_file_has_undedacted_data(zip_obj, filename):
    # checking that file contains at list one unredacted tag <ud>
    with zip_obj.open(filename) as f:
        for line in f.readlines():
            if regex_unredacted.search(line.decode()) is not None:
                return
    assert False, f'file {filename} is expected to have unredacted data'


def assert_file_is_redacted(zip_obj, filename):
    with zip_obj.open(filename) as f:
        for line in f.readlines():
            assert regex_unredacted.search(line.decode()) is None, \
                   f'line {line} in {filename} is unredacted'


def assert_tasks_are_successfull(zip_obj, filename, tasknames):
    regex_dict = {t: re.compile(f'{t}.* - OK') for t in tasknames}
    res = {t: False for t in tasknames}
    with zip_obj.open(filename) as f:
        for line in f.readlines():
            for t in res:
                if not res[t]:
                    if regex_dict[t].search(line.decode()) is not None:
                        print(f'task "{t}" found in log')
                        res[t] = True
    for t in res:
        assert res[t], f'Failed to find task "{t}" in logs'


def assert_cbcollect_returns_incorrect_password(node, zip_dir, **kwargs):
    tasks = ['Couchbase config', 'Chronicle dump', 'Chronicle logs']
    task_regexp = '|'.join(tasks) + '|cbcollect_info'

    zip_filename = Path(zip_dir) / 'incorrect_password_dump'
    _, err = run_cbcollect(node, zip_filename, task_regexp=task_regexp,
                           expected_exit_code=2, **kwargs)

    incorrect_password_msg = 'Incorrect master password'
    assert incorrect_password_msg in err, \
          f'{incorrect_password_msg} not present in ' \
          f'cbcollect error output: {err}'
