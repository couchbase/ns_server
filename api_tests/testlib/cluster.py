# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.


class Cluster:
    def __init__(self, urls, processes, auth, memsize, is_enterprise, is_71,
                 is_elixir, is_serverless, is_dev_preview, data_path):
        self.urls = urls
        self.processes = processes
        self.auth = auth
        self.memsize = memsize
        self.is_enterprise = is_enterprise
        self.is_71 = is_71
        self.is_elixir = is_elixir
        self.is_serverless = is_serverless
        self.is_dev_preview = is_dev_preview
        self.data_path = data_path

    def __str__(self):
        return self.__dict__.__str__()
