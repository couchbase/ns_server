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
import string
import random
import base64
import os
from scramp import ScramClient
import requests


class AuthnTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=1)


    def setup(self, cluster):
        self.testEndpoint = "/pools/default"
        username = randomStr(8)
        wrong_user = randomStr(8)
        password = randomStr(8)
        wrong_password = randomStr(8)
        self.creds = (username, password)
        self.wrong_pass_creds = (username, wrong_password)
        self.wrong_user_creds = (wrong_user, password)
        testlib.put_succ(cluster, f'/settings/rbac/users/local/{username}',
                         data={'roles': 'admin', 'password': password})


    def teardown(self, cluster):
        (username, password) = self.creds
        testlib.ensure_deleted(cluster, f'/settings/rbac/users/local/{username}')


    def basic_auth_test(self, cluster):
        testlib.get_fail(cluster, '/pools/default', 401, auth=None)
        testlib.get_succ(cluster, self.testEndpoint, auth=self.creds)
        r = testlib.get_fail(cluster, self.testEndpoint, 401,
                             auth=self.wrong_user_creds)
        assert 'WWW-Authenticate' in r.headers
        assert 'Basic realm="Couchbase Server Admin / REST"' == r.headers['WWW-Authenticate']
        r = testlib.get_fail(cluster, self.testEndpoint, 401, auth=self.wrong_pass_creds)
        assert 'WWW-Authenticate' in r.headers
        assert 'Basic realm="Couchbase Server Admin / REST"' == r.headers['WWW-Authenticate']
        r = testlib.get_fail(cluster, self.testEndpoint, 401,
                             auth=self.wrong_pass_creds,
                             headers={'invalid-auth-response':'on'})
        assert 'WWW-Authenticate' not in r.headers


    def scram_sha512_test(self, cluster):
        self.scram_sha_test_mech(cluster, 'SCRAM-SHA-512')


    def scram_sha256_test(self, cluster):
        self.scram_sha_test_mech(cluster, 'SCRAM-SHA-256')


    def scram_sha1_test(self, cluster):
        self.scram_sha_test_mech(cluster, 'SCRAM-SHA-1')


    def scram_sha_test_mech(self, cluster, mech):
        r = scram_sha_auth(mech, self.testEndpoint, self.creds, cluster)
        testlib.assert_http_code(200, r)
        r = scram_sha_auth(mech, self.testEndpoint, self.wrong_pass_creds, cluster)
        testlib.assert_http_code(401, r)
        r = scram_sha_auth(mech, self.testEndpoint, self.wrong_user_creds, cluster)
        testlib.assert_http_code(401, r)


    def local_token_test(self, cluster):
        tokenPath = os.path.join(cluster.data_path, "localtoken")
        with open(tokenPath, 'r') as f:
            token = f.read().rstrip()
            testlib.get_succ(cluster, '/diag/password',
                             auth=('@localtoken', token))
            testlib.get_fail(cluster, '/diag/password', 401,
                             auth=('@localtoken', token + 'foo'))


    def uitoken_test(self, cluster):
        (user, password) = self.creds
        (wrong_user, wrong_password) = self.wrong_pass_creds
        testlib.post_fail(cluster, '/uilogin', 400, auth=None,
                          data={'user': wrong_user, 'password': wrong_password})
        session = requests.Session()
        url = cluster.nodes[0].url + '/uilogin'
        headers={'Host': randomStr(8), 'ns-server-ui': 'yes'}
        r = session.post(cluster.nodes[0].url + '/uilogin',
                         data={'user': user, 'password': password},
                         headers=headers)
        testlib.assert_http_code(200, r)
        r = session.get(cluster.nodes[0].url + self.testEndpoint, headers=headers)
        testlib.assert_http_code(200, r)
        r = session.post(cluster.nodes[0].url + '/uilogout', headers=headers)
        testlib.assert_http_code(200, r)
        r = session.get(cluster.nodes[0].url + self.testEndpoint, headers=headers)
        testlib.assert_http_code(401, r)


def randomStr(n):
    return ''.join(random.choices(string.ascii_lowercase +
                                  string.digits, k=n))


def headerToScramMsg(header):
    replyDict = {}
    for t in header.split(","):
        k, v = tuple(t.split("=", 1))
        replyDict[k] = v
    assert 'data' in replyDict
    assert 'sid' in replyDict
    return replyDict


def scram_sha_auth(mech, testEndpoint, creds, cluster):
    (user, password) = creds
    c = ScramClient([mech], user, password)
    cfirst = c.get_client_first()
    cfirstBase64 = base64.b64encode(cfirst.encode('ascii')).decode()
    msg = f'realm="Couchbase Server Admin / REST",data={cfirstBase64}'
    r = testlib.get_fail(cluster, testEndpoint, 401, auth=None,
                         headers={'Authorization': mech + ' ' + msg})
    assert 'WWW-Authenticate' in r.headers
    reply = r.headers['WWW-Authenticate']
    assert reply.startswith(mech + ' ')
    reply = reply[len(mech)+1:]
    replyDict = headerToScramMsg(reply)
    sid = replyDict['sid']
    sfirst = base64.b64decode(replyDict['data'].encode('ascii')).decode()
    c.set_server_first(sfirst)
    cfinal = c.get_client_final()
    cfinalBase64 = base64.b64encode(cfinal.encode('ascii')).decode()
    msg = f'sid={sid},data={cfinalBase64}'
    r = testlib.get(cluster, testEndpoint, auth=None,
                    headers={'Authorization': mech + ' ' + msg})
    if 'Authentication-Info' in r.headers:
        authInfo = r.headers['Authentication-Info']
        authInfoDict = headerToScramMsg(authInfo)
        ssignature = base64.b64decode(authInfoDict['data'].encode('ascii')).decode()
        c.set_server_final(ssignature)
    return r
