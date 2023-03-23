# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.


class Node:
    def __init__(self, host, port, auth):
        self.hostname = f"{host}:{port}"
        self.url = "http://" + self.hostname
        self.host = host
        self.port = port
        self.auth = auth
