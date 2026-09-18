# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""JWT settings survive an upgrade from the 8.0.x format.

Before 8.5 every string in jwt_settings was a list of utf8 bytes. 8.5
holds them as binaries. MB-73361 made that switch and MB-73362 added the
conversion: get_settings/0 converts on read until cluster compat reaches
8.5, and chronicle_upgrade_to_85/1 rewrites the stored term once it
does.

to_binary_format_test_/0 pins the conversion against a term the test itself
writes. This suite feeds it a term an 8.0.x node wrote.

Enterprise Analytics is the only deployment that can hold such a term. It
shipped JWT on ns_server 8.0.x by setting jwt_enabled in its config profile,
which let /settings/jwt past the developer preview gate. CI has no EA build to
upgrade from, so the old node here is a stock morpheus node with that same
flag set. The flag is all that separated the two: the endpoint, the validators
and the writer behind it are the ones EA shipped.

Developer preview would open the same gate. It also changes the role list that
RbacRolesUpgradeChecks captures on the same cluster, so it is not an option.
"""

import os
import subprocess
import time

import jwt
import testlib
from testlib.upgrade_test_base import UpgradeChecks as UpgradeCheckSuite
from testlib.util import Service

ISSUER = "upgrade-test-issuer"
AUDIENCE = "upgrade-test-audience"
SUBJECT = "upgrade-test-subject"
SECRET = "s" * 64
GROUP = "jwt_upgrade_group"

# Non-ASCII in the pattern is the point of the conversion. The pattern and the
# token's group are utf8 bytes on both lines, so the rule matches before the
# upgrade as well as after it.
TOKEN_GROUP = "grün-" + GROUP
GROUPS_MAP = "^grün-(.*)$ \\1"


ENABLE_JWT_CODE = (
    "config_profile:set_data([{jwt_enabled, true} | config_profile:get()]),"
    "config_profile:get_bool(jwt_enabled).")


def shape_code(pred):
    """Erlang naming every stored string that is not of the given type."""
    return (
        "{ok, {#{issuers := Is}, _}} = chronicle_kv:get(kv, jwt_settings),"
        "[{Name, Props}] = maps:to_list(Is),"
        "Rules = maps:get(groups_maps, Props),"
        "Vals = [{issuer_name, Name},"
        "        {sub_claim, maps:get(sub_claim, Props)},"
        "        {aud_claim, maps:get(aud_claim, Props)},"
        "        {groups_claim, maps:get(groups_claim, Props)}]"
        "       ++ [{audience, A} || A <- maps:get(audiences, Props)]"
        "       ++ lists:flatmap(fun({P, T}) ->"
        "                               [{rule_pattern, P},"
        "                                {rule_template, T}]"
        "                       end, Rules),"
        f"[K || {{K, V}} <- Vals, not erlang:{pred}(V)]."
    )


class JwtUpgradeChecks(UpgradeCheckSuite):

    def before_upgrade(self):
        # JWT did not exist before 8.0, so there is no older format to carry.
        self.applicable = self.compat_mode == '8.0'
        if not self.applicable:
            return

        # Reproduce the Enterprise Analytics profile on the old node. set_data
        # writes a persistent_term, so this is node local and is gone when the
        # node is ejected.
        assert testlib.diag_eval(
            self.old_node, ENABLE_JWT_CODE
        ).text.strip() == "true", "jwt_enabled not set on the old node"

        # ro_admin covers the REST check. bucket_admin covers the memcached
        # check, which authenticates against the bucket.
        testlib.put_succ(
            self.old_node, f"/settings/rbac/groups/{GROUP}",
            data={"roles": f"ro_admin,bucket_admin[{self.bucket_name}]",
                  "description": "JWT upgrade test group"})

        testlib.put_succ(self.old_node, "/settings/jwt", json={
            "enabled": True,
            "issuers": [{
                "name": ISSUER,
                "signingAlgorithm": "HS256",
                "sharedSecret": SECRET,
                "audClaim": "aud",
                "audienceHandling": "any",
                "audiences": [AUDIENCE],
                "subClaim": "sub",
                "jitProvisioning": True,
                "groupsClaim": "groups",
                "groupsMaps": [GROUPS_MAP],
            }],
        })

        self.assert_stored_shape(self.old_node, "is_list")
        self.assert_authenticates(self.old_node)

    def mixed_cluster_checks(self):
        if not self.applicable:
            return

        # Nothing rewrites the stored term while a node that cannot read the
        # new format is still in the cluster.
        self.assert_stored_shape(self.old_node, "is_list")

        # The 8.5 node reads the old term through the conversion in
        # get_settings/0. This is the case a customer is in for the length of
        # a rolling upgrade.
        self.assert_authenticates(self.new_node)
        self.assert_authenticates(self.old_node)

        # The two auth paths are gated in different places. REST is gated on
        # the settings endpoint. OAUTHBEARER was gated on the memcached auth
        # path itself, and MB-73362 removed that gate so SASL keeps working
        # through a rolling upgrade. REST passing says nothing about SASL.
        self.assert_memcached_authenticates(self.new_node)

        # The 8.5 node refuses to serve its own settings endpoint until
        # compat reaches 8.5.
        testlib.get_fail(self.new_node, "/settings/jwt", expected_code=400)

    def post_upgrade_checks(self):
        if not self.applicable:
            return

        self.assert_stored_shape(self.new_node, "is_binary")
        self.assert_authenticates(self.new_node)

        issuer = testlib.get_succ(
            self.new_node, "/settings/jwt").json()["issuers"][0]
        # A representation mismatch reaches JSON as an array of integers.
        testlib.assert_eq(issuer["name"], ISSUER, name="name")
        testlib.assert_eq(issuer["subClaim"], "sub", name="subClaim")
        testlib.assert_eq(issuer["audiences"], [AUDIENCE], name="audiences")
        testlib.assert_eq(issuer["groupsMaps"], [GROUPS_MAP],
                          name="groupsMaps")

        testlib.ensure_deleted(self.new_node, "/settings/jwt")
        testlib.ensure_deleted(self.new_node,
                               f"/settings/rbac/groups/{GROUP}")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def assert_stored_shape(self, node, pred):
        result = testlib.diag_eval(node, shape_code(pred)).text.strip()
        assert result == "[]", \
            f"stored jwt_settings fields failing {pred}: {result}"

    def token(self):
        return jwt.encode({"iss": ISSUER,
                           "sub": SUBJECT,
                           "aud": AUDIENCE,
                           "groups": [TOKEN_GROUP],
                           "exp": int(time.time()) + 3600},
                          SECRET, algorithm="HS256")

    def assert_authenticates(self, node):
        """A settings write reaches jwt_cache asynchronously, so poll."""
        headers = {"Authorization": f"Bearer {self.token()}"}
        testlib.poll_for_condition(
            lambda: testlib.get(node, "/pools/default", auth=None,
                                headers=headers).status_code == 200,
            sleep_time=0.5, timeout=60,
            msg=f"authenticate with a JWT against {node}")

    def assert_memcached_authenticates(self, node):
        """memcached enables external auth asynchronously, so poll."""
        mcstat = testlib.get_utility_path("mcstat")
        assert os.path.exists(mcstat), f"mcstat not found at {mcstat}"
        cmd = [mcstat,
               "-h", node.host,
               "-p", str(node.tls_service_port(Service.KV)),
               "--sasl_mechanism", "OAUTHBEARER",
               "--user", SUBJECT,
               "--password", self.token(),
               "--bucket", self.bucket_name,
               "--tls",
               "--no-peer-verify"]
        testlib.poll_for_condition(
            lambda: subprocess.run(cmd, capture_output=True,
                                   text=True).returncode == 0,
            sleep_time=0.5, timeout=60,
            msg=f"authenticate with OAUTHBEARER against {node}")
