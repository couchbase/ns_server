# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import os
import json
import testlib
from testlib.test_tag_decorator import tag, Tag

# These keys are used by the audit descriptor/API to describe an event
# itself (its id, name and description), so they must not also appear as
# a key within an event's mandatory_fields or optional_fields.
# These should be kept in sync with KV's daemon/mcaudit.cc file where
# these fields are overwritten.
RESERVED_EVENT_FIELD_KEYS = ["id", "name", "description"]

AUDIT_DESCRIPTOR_PATH = os.path.join(testlib.get_etc_dir(),
                                     "audit_descriptor.json")


class AuditTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=1)

    def setup(self):
        pass

    def teardown(self):
        pass

    @tag(Tag.LowUrgency)
    def audit_descriptor_no_reserved_field_keys_test(self):
        with open(AUDIT_DESCRIPTOR_PATH) as f:
            descriptor = json.load(f)

        violations = [(event.get("name"), fields_key, key)
                      for event in descriptor["events"]
                      for fields_key in ("mandatory_fields",
                                        "optional_fields")
                      for key in event.get(fields_key, {})
                      if key in RESERVED_EVENT_FIELD_KEYS]

        testlib.assert_eq(violations, [])
