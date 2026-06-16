# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in
# that file, in accordance with the Business Source License, use of this
# software will be governed by the Apache License, Version 2.0, included in
# the file licenses/APL2.txt.
import testlib

BASE_PATH = "/pools/default/externalCatalogs"


def catalog_path(name):
    return f"{BASE_PATH}/{name}"


def get_catalogs_from_response(response_json):
    return {k: v for k, v in response_json.items()
            if k != "uid"}


class ExternalCatalogTests(testlib.BaseTestSet):

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(
            buckets=[],
            min_num_nodes=1,
            min_num_connected=1,
            balanced=True,
            include_services=[testlib.Service.QUERY])

    def setup(self):
        testlib.set_config_key(self.cluster,
                               'ignore_external_catalog_validation_errors',
                               True)
        self.set_forced_validation_results()


    def set_forced_validation_results(self):
        testlib.diag_eval(self.cluster,
                          'ns_config:set(' \
                          'forced_external_catalog_validation_results, ' \
                          '{ok, #{<<"param1">> => <<"value1">>,' \
                          '       <<"param2">> => <<"value2">>}})')

    def set_forced_validation_results_error(self):
        testlib.diag_eval(self.cluster,
                          'ns_config:set(' \
                          'forced_external_catalog_validation_results, ' \
                          '{errors, [{<<"param1">>, <<"Unsupported">>}]})')

    def teardown(self):
        pass

    def test_teardown(self):
        response = testlib.get_succ(self.cluster, BASE_PATH).json()
        catalogs = get_catalogs_from_response(response)
        for catalog in catalogs:
            testlib.ensure_deleted(
                self.cluster, catalog_path(catalog))

        # Some tests care about the catalog limit which is the same as the
        # collections limit as catalogs data is consumed via collections.
        testlib.diag_eval(
            self.cluster,
            'ns_config:delete(max_collections_count)')

    def get_empty_list_test(self):
        r = testlib.get_succ(self.cluster, BASE_PATH)
        body = r.json()
        testlib.assert_in("uid", body)
        catalogs = get_catalogs_from_response(body)
        testlib.assert_eq({}, catalogs)

    def create_catalog_test(self):
        r = testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "test-catalog"})
        body = r.json()
        testlib.assert_in("rev", body)

        r = testlib.get_succ(
            self.cluster, catalog_path("test-catalog"))
        body = r.json()
        testlib.assert_in("rev", body)

    def create_duplicate_catalog_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "dup-catalog"})
        testlib.post_fail(
            self.cluster, BASE_PATH, expected_code=409,
            data={"name": "dup-catalog"})

    def create_catalog_missing_name_test(self):
        testlib.post_fail(
            self.cluster, BASE_PATH, expected_code=400,
            data={})

    def create_catalog_invalid_name_test(self):
        testlib.post_fail(
            self.cluster, BASE_PATH, expected_code=400,
            data={"name": "bad name!"})

    def get_nonexistent_catalog_test(self):
        testlib.get_fail(
            self.cluster,
            catalog_path("nonexistent"),
            expected_code=404)

    def list_multiple_catalogs_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "catalog-a"})
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "catalog-b"})

        r = testlib.get_succ(self.cluster, BASE_PATH)
        catalogs = get_catalogs_from_response(r.json())
        testlib.assert_in("catalog-a", catalogs)
        testlib.assert_in("catalog-b", catalogs)

    def modify_catalog_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "modify-catalog"})

        testlib.put_succ(
            self.cluster, catalog_path("modify-catalog"),
            data={"param1": "value1"}),

        r = testlib.get_succ(
            self.cluster, catalog_path("modify-catalog"))
        testlib.assert_eq("value1", r.json()["param1"])

    def modify_nonexistent_catalog_test(self):
        testlib.put_fail(
            self.cluster,
            catalog_path("nonexistent"),
            expected_code=404,
            data={})

    def patch_catalog_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "patch-catalog"})

        r = testlib.patch_succ(
            self.cluster,
            catalog_path("patch-catalog"),
            data={"param1": "value1"})
        body = r.json()
        testlib.assert_eq("value1", body["param1"])

        r = testlib.get_succ(
            self.cluster,
            catalog_path("patch-catalog"))
        testlib.assert_eq("value1", r.json()["param1"])

    def patch_catalog_preserves_existing_params_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "patch-preserve",
                  "param1": "value1"})

        testlib.patch_succ(
            self.cluster,
            catalog_path("patch-preserve"),
            data={"param2": "value2"})

        r = testlib.get_succ(
            self.cluster,
            catalog_path("patch-preserve"))
        body = r.json()
        testlib.assert_eq("value1", body["param1"])
        testlib.assert_eq("value2", body["param2"])

    def patch_nonexistent_catalog_test(self):
        testlib.patch_fail(
            self.cluster,
            catalog_path("nonexistent"),
            expected_code=404,
            data={"param": "value"})

    def patch_catalog_name_prohibited_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "no-rename"})

        testlib.patch_fail(
            self.cluster,
            catalog_path("no-rename"),
            expected_code=400,
            data={"name": "new-name"})

    def delete_catalog_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "to-delete"})

        testlib.delete_succ(
            self.cluster, catalog_path("to-delete"))

        testlib.get_fail(
            self.cluster,
            catalog_path("to-delete"),
            expected_code=404)

        r = testlib.get_succ(self.cluster, BASE_PATH)
        catalogs = get_catalogs_from_response(r.json())
        testlib.assert_not_in("to-delete", catalogs)

    def delete_nonexistent_catalog_test(self):
        testlib.delete_fail(
            self.cluster,
            catalog_path("nonexistent"),
            expected_code=404)

    def get_catalog_returns_rev_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "get-rev"})
        r = testlib.get_succ(
            self.cluster, catalog_path("get-rev"))
        testlib.assert_in("rev", r.json())

    def list_catalogs_returns_rev_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "list-rev"})
        r = testlib.get_succ(self.cluster, BASE_PATH)
        catalogs = get_catalogs_from_response(r.json())
        for cat in catalogs.values():
            testlib.assert_in("rev", cat)

    def uid_increments_test(self):
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid0 = r.json()["uid"]

        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "uid-cat-a"})
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid1 = r.json()["uid"]
        testlib.assert_eq(uid0 + 1, uid1)

        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "uid-cat-b"})
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid2 = r.json()["uid"]
        testlib.assert_eq(uid0 + 2, uid2)

        testlib.put_succ(
            self.cluster,
            catalog_path("uid-cat-a"),
            data={"param1": "value1"})
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid3 = r.json()["uid"]
        testlib.assert_eq(uid0 + 3, uid3)

        testlib.delete_succ(
            self.cluster,
            catalog_path("uid-cat-a"))
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid4 = r.json()["uid"]
        testlib.assert_eq(uid0 + 4, uid4)

    def rev_matches_uid_test(self):
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid0 = r.json()["uid"]

        r = testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "rev-uid"})
        testlib.assert_eq(uid0 + 1, r.json()["rev"])

        r = testlib.put_succ(
            self.cluster,
            catalog_path("rev-uid"),
            data={"param1": "value1"})
        testlib.assert_eq(uid0 + 2, r.json()["rev"])

    def cas_put_with_correct_rev_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "cas-ok"})

        r = testlib.get_succ(
            self.cluster, catalog_path("cas-ok"))
        rev = r.json()["rev"]

        r2 = testlib.put_succ(
            self.cluster, catalog_path("cas-ok"),
            data={"rev": rev})
        body = r2.json()
        new_rev = body["rev"]
        testlib.assert_not_eq(rev, new_rev)

    def cas_put_with_stale_rev_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "cas-stale"})

        r = testlib.get_succ(
            self.cluster,
            catalog_path("cas-stale"))
        stale_rev = r.json()["rev"]

        # Modify the catalog to advance the revision
        testlib.put_succ(
            self.cluster,
            catalog_path("cas-stale"),
            data={})

        # The stale rev should now cause a 409
        testlib.put_fail(
            self.cluster,
            catalog_path("cas-stale"),
            expected_code=409,
            data={"rev": stale_rev})

    def cas_put_without_rev_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "cas-none"})

        # PUT without rev should succeed unconditionally
        r = testlib.put_succ(
            self.cluster, catalog_path("cas-none"),
            data={})
        testlib.assert_in("rev", r.json())

    def cas_put_rev_updates_after_modify_test(self):
        r1 = testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "cas-update"})
        rev1 = r1.json()["rev"]

        r2 = testlib.put_succ(
            self.cluster,
            catalog_path("cas-update"),
            data={"rev": rev1})
        rev2 = r2.json()["rev"]

        # Rev should change after a modification
        assert rev1 != rev2, \
            "rev should change after modification"

        # The new rev should work for the next CAS
        testlib.put_succ(
            self.cluster,
            catalog_path("cas-update"),
            data={"rev": rev2})

    def patch_returns_rev_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "patch-rev"})

        r = testlib.patch_succ(
            self.cluster,
            catalog_path("patch-rev"),
            data={"param1": "value1"})
        testlib.assert_in("rev", r.json())

    def patch_advances_rev_test(self):
        r1 = testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "patch-adv"})
        rev1 = r1.json()["rev"]

        r2 = testlib.patch_succ(
            self.cluster,
            catalog_path("patch-adv"),
            data={"param1": "value1"})
        rev2 = r2.json()["rev"]

        assert rev1 != rev2, \
            "rev should change after patch"

    def cas_patch_with_correct_rev_test(self):
        r1 = testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "cas-patch-ok"})
        rev = r1.json()["rev"]

        r2 = testlib.patch_succ(
            self.cluster,
            catalog_path("cas-patch-ok"),
            data={"param1": "value1", "rev": rev})
        body = r2.json()
        testlib.assert_eq("value1", body["param1"])
        testlib.assert_in("rev", body)

    def cas_patch_with_stale_rev_test(self):
        r1 = testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "cas-patch-stale"})
        stale_rev = r1.json()["rev"]

        # Advance the revision
        testlib.patch_succ(
            self.cluster,
            catalog_path("cas-patch-stale"),
            data={"param1": "value1"})

        # The stale rev should cause a 409
        testlib.patch_fail(
            self.cluster,
            catalog_path("cas-patch-stale"),
            expected_code=409,
            data={"param1": "value2",
                  "rev": stale_rev})

    def cas_patch_without_rev_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "cas-patch-none"})

        # PATCH without rev should succeed
        r = testlib.patch_succ(
            self.cluster,
            catalog_path("cas-patch-none"),
            data={"param1": "value1"})
        testlib.assert_eq("value1", r.json()["param1"])

    def cas_patch_rev_chains_test(self):
        r1 = testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "cas-patch-chain"})
        rev1 = r1.json()["rev"]

        r2 = testlib.patch_succ(
            self.cluster,
            catalog_path("cas-patch-chain"),
            data={"param1": "value1", "rev": rev1})
        rev2 = r2.json()["rev"]

        assert rev1 != rev2, \
            "rev should change after patch"

        # The new rev should work for the next CAS
        r3 = testlib.patch_succ(
            self.cluster,
            catalog_path("cas-patch-chain"),
            data={"param2": "value2", "rev": rev2})
        rev3 = r3.json()["rev"]

        assert rev2 != rev3, \
            "rev should change after second patch"

        # Verify both params are present
        r = testlib.get_succ(
            self.cluster,
            catalog_path("cas-patch-chain"))
        body = r.json()
        testlib.assert_eq("value1", body["param1"])
        testlib.assert_eq("value2", body["param2"])

    def catalog_limit_test(self):
        # Set the max collections count to a low value
        # to test the catalog limit.
        testlib.diag_eval(
            self.cluster,
            'ns_config:set(max_collections_count, 2)')

        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "limit-a"})
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "limit-b"})

        # Third catalog should fail
        testlib.post_fail(
            self.cluster, BASE_PATH,
            expected_code=400,
            data={"name": "limit-c"})

        # Deleting one should allow creation again
        testlib.delete_succ(
            self.cluster,
            catalog_path("limit-a"))
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "limit-c"})


    def put_manifest_empty_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "pm-existing"})

        r = testlib.put_succ(
            self.cluster, BASE_PATH,
            json={})
        body = r.json()
        testlib.assert_in("uid", body)
        catalogs = get_catalogs_from_response(body)
        testlib.assert_eq({}, catalogs)

        # Existing catalog should be gone
        testlib.get_fail(
            self.cluster,
            catalog_path("pm-existing"),
            expected_code=404)

    def put_manifest_replaces_all_test(self):
        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "pm-old"})

        r = testlib.put_succ(
            self.cluster, BASE_PATH,
            json={"pm-new-a": {"param1": "value1"},
                  "pm-new-b": {"param2": "value2"}})
        body = r.json()
        catalogs = get_catalogs_from_response(body)
        testlib.assert_in("pm-new-a", catalogs)
        testlib.assert_in("pm-new-b", catalogs)
        testlib.assert_not_in("pm-old", catalogs)

        testlib.get_fail(
            self.cluster,
            catalog_path("pm-old"),
            expected_code=404)

    def put_manifest_sets_rev_on_all_test(self):
        r = testlib.put_succ(
            self.cluster, BASE_PATH,
            json={"pm-rev-a": {"param1": "value1"},
                  "pm-rev-b": {"param2": "value2"}})
        body = r.json()
        uid = body["uid"]
        catalogs = get_catalogs_from_response(body)
        for cat in catalogs.values():
            testlib.assert_in("rev", cat)
            testlib.assert_eq(uid, cat["rev"])

    def put_manifest_increments_uid_test(self):
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid0 = r.json()["uid"]

        r = testlib.put_succ(
            self.cluster, BASE_PATH,
            json={"pm-uid-a": {}})
        uid1 = r.json()["uid"]
        testlib.assert_eq(uid0 + 1, uid1)

    def put_manifest_uid_prohibited_test(self):
        # uid as a non-object is rejected by the json_map parser
        testlib.put_fail(
            self.cluster, BASE_PATH,
            expected_code=400,
            json={"uid": 0,
                  "pm-cat": {}})
        # uid as a JSON object is rejected by the name validator
        testlib.put_fail(
            self.cluster, BASE_PATH,
            expected_code=400,
            json={"uid": {},
                  "pm-cat": {}})

    def put_manifest_uid_not_restored_test(self):
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid_before = r.json()["uid"]

        # PUT manifest with no catalogs to get a new uid
        r = testlib.put_succ(
            self.cluster, BASE_PATH,
            json={})
        uid_after = r.json()["uid"]

        # uid must advance, not stay the same or go backwards
        assert uid_after > uid_before, \
            f"uid should increase: {uid_before} -> {uid_after}"

    def put_manifest_valid_on_uid_match_test(self):
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid = r.json()["uid"]

        # PUT with a matching validOnUid should succeed
        r = testlib.put_succ(
            self.cluster,
            f"{BASE_PATH}?validOnUid={uid}",
            json={"vou-match": {}})
        body = r.json()
        catalogs = get_catalogs_from_response(body)
        testlib.assert_in("vou-match", catalogs)
        testlib.assert_eq(uid + 1, body["uid"])

    def put_manifest_valid_on_uid_mismatch_test(self):
        r = testlib.get_succ(self.cluster, BASE_PATH)
        uid = r.json()["uid"]

        # PUT with a stale validOnUid should fail and not modify
        # the manifest
        testlib.put_fail(
            self.cluster,
            f"{BASE_PATH}?validOnUid={uid + 1}",
            expected_code=400,
            json={"vou-stale": {}})

        r = testlib.get_succ(self.cluster, BASE_PATH)
        body = r.json()
        catalogs = get_catalogs_from_response(body)
        testlib.assert_not_in("vou-stale", catalogs)
        testlib.assert_eq(uid, body["uid"])

    def put_manifest_valid_on_uid_invalid_test(self):
        testlib.put_fail(
            self.cluster,
            f"{BASE_PATH}?validOnUid=notanumber",
            expected_code=400,
            json={"vou-bad": {}})

    def put_manifest_invalid_name_test(self):
        testlib.put_fail(
            self.cluster, BASE_PATH,
            expected_code=400,
            json={"bad name@": {}})

    def put_manifest_invalid_catalog_value_test(self):
        testlib.put_fail(
            self.cluster, BASE_PATH,
            expected_code=400,
            json={"pm-cat": "not-an-object"})

    def put_manifest_invalid_json_test(self):
        testlib.request(
            'PUT', self.cluster, BASE_PATH,
            expected_code=400,
            data=b"not json at all",
            headers={"Content-Type": "application/json"})

    def put_manifest_not_object_test(self):
        testlib.put_fail(
            self.cluster, BASE_PATH,
            expected_code=400,
            json=["pm-cat"])

    def put_manifest_limit_test(self):
        testlib.diag_eval(
            self.cluster,
            'ns_config:set(max_collections_count, 2)')

        testlib.put_fail(
            self.cluster, BASE_PATH,
            expected_code=400,
            json={"pm-limit-a": {},
                  "pm-limit-b": {},
                  "pm-limit-c": {}})

        # Exactly at limit should succeed
        testlib.put_succ(
            self.cluster, BASE_PATH,
            json={"pm-limit-a": {},
                  "pm-limit-b": {}})

    def put_manifest_invalid_catalog_params_test(self):
        testlib.put_succ(
            self.cluster, BASE_PATH,
            json={"pm-limit-a": {"param1": "value1"}})

        self.set_forced_validation_results_error()

        # Check that an invalid parameter errors
        testlib.put_fail(
            self.cluster, BASE_PATH,
            expected_code=400,
            json={"pm-limit-a": {"param1": "value3"}})

        self.set_forced_validation_results()

    def pools_default_includes_catalogs_test(self):
        r = testlib.get_succ(
            self.cluster, "/pools/default")
        body = r.json()
        testlib.assert_in("externalCatalogsManifestUid", body)
        rev = body["externalCatalogsManifestUid"]

        testlib.post_succ(
            self.cluster, BASE_PATH,
            data={"name": "pool-cat"})

        r = testlib.get_succ(
            self.cluster, "/pools/default")
        body = r.json()
        testlib.assert_in("externalCatalogsManifestUid", body)
        testlib.assert_eq(rev + 1, body["externalCatalogsManifestUid"])
