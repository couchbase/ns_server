# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import testlib
import http.client


class WebServerTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements()

    def setup(self):
        pass

    def teardown(self):
        pass

    ## Sending wrong path in http request: "GET \ HTTP1.1"
    def invalid_uri_in_request_test(self):
        node = self.cluster.connected_nodes[0]
        conn = http.client.HTTPConnection(node.host, node.port)
        try:
            host = testlib.maybe_add_brackets(node.host)
            conn.request('GET', '\\', headers={'Host': f'{host}:{node.port}'})
            response = conn.getresponse()
            testlib.assert_eq(response.status, 400)
            testlib.assert_eq(response.reason, 'Bad Request')
        finally:
            conn.close()
