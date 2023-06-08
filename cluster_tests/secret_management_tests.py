# @author Couchbase <info@couchbase.com>
# @copyright 2023 Couchbase, Inc.
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
import testlib
import re
import os
import signal


class SecretManagementTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(edition="Enterprise")

    def setup(self, cluster):
        r = testlib.get_succ(cluster, "/nodes/self/secretsManagement")
        r = r.json()
        assert r['state'] == 'default', \
               f"secret management is supposed to be turned off"

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        change_password(cluster, password='')

    def change_password_test(self, cluster):
        data = testlib.random_str(32)
        encrypted_data = encrypt(cluster, data)
        check_decrypt(cluster, encrypted_data, data)

        password = change_password(cluster)
        check_decrypt(cluster, encrypted_data, data)
        encrypted_data = encrypt(cluster, data)
        change_password(cluster, password='')
        check_decrypt(cluster, encrypted_data, data)

    def gosecrets_crash_test(self, cluster):
        password = change_password(cluster)

        data = testlib.random_str(32)
        encrypted_data = encrypt(cluster, data)

        kill_gosecrets(cluster)
        testlib.poll_for_condition(gosecrets_started_fun(cluster),
                                   sleep_time=0.2,
                                   timeout=60,
                                   verbose=True)
        check_decrypt(cluster, encrypted_data, data)


def encrypt(cluster, s):
    res = testlib.diag_eval(
            cluster,
            '{ok, B} = ' f'encryption_service:encrypt(<<"{s}">>),'
            'R = base64:encode_to_string(B),'
            '"Success:" ++ R.')
    search_res = re.search('"Success:(.*)"', res.text)
    assert search_res is not None, f"unexpected encrypt result: {res.text}"
    return search_res.group(1)


def decrypt(cluster, s):
    res = testlib.diag_eval(
            cluster,
            f'B = base64:decode("{s}"),'
            '{ok, R} = encryption_service:decrypt(B),'
            '"Success:" ++ binary_to_list(R).')
    search_res = re.search('"Success:(.*)"', res.text)
    assert search_res is not None, f"unexpected decrypt result: {res.text}"
    return search_res.group(1)


def check_decrypt(cluster, encrypted_data, expected_data):
    decrypted_data = decrypt(cluster, encrypted_data)

    assert expected_data == decrypted_data, \
           f"decrypted data doesn't match the original. " \
           "Expected: {expected_data}, Got: {decrypted_data}"


def kill_gosecrets(cluster):
    r = testlib.diag_eval(cluster, "encryption_service:os_pid().")
    gosecrets_pid = int(r.text)
    os.kill(gosecrets_pid, signal.SIGKILL)


def change_password(cluster, password=None):
    if password is None:
        password = testlib.random_str(8)

    testlib.post_succ(cluster, "/node/controller/changeMasterPassword",
                      data={'newPassword': password})

    return password


def gosecrets_started_fun(cluster):
    def fun():
        r = testlib.diag_eval(cluster, "catch encryption_service:os_pid().")
        try:
            int(r.text)
            return True
        except ValueError:
            return False
    return fun
