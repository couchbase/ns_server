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

import testlib

class DummyTestSet(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=1)

    def setup(self, cluster):
        pass

    def teardown(self, cluster):
        pass

    def dummy1_test(self, cluster):
        pass

    def dummy2_test(self, cluster):
        pass
