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
        pass

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


def run_cbcollect(node, path_to_zip, redaction_level=None, task_regexp=None):
    initargs = os.path.join(node.data_path(), "initargs")
    args = [testlib.get_utility_path('cbcollect_info'),
            "--initargs", initargs, str(path_to_zip)]
    env = {"PATH": os.environ['PATH'],
           "PYTHONPATH": testlib.get_pylib_dir()}

    if redaction_level is not None:
        args.extend(["--log-redaction-level", redaction_level])

    if task_regexp is not None:
        args.extend(["--task-regexp", task_regexp])

    r = subprocess.run(args, capture_output=True, env=env)
    assert r.returncode == 0


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
