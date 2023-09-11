# @author Couchbase <info@couchbase.com>
# @copyright 2023-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

import testlib
import json
from jsondiff import diff
import copy

BUCKETS_ENDPOINT = "/pools/default/buckets"

# Manifests obtained from prior release to ensure it is PUTable in current
# release. These were obtained via /pools/default/buckets/<bucket>/scopes
# GET requests on a node running the neo release.

# Future enhancement (MB-58699):
# It would be nice to obtain these by first starting a down-rev node using
# cluster_run --pretend-version, creating the buckets, getting the manifests,
# and then tearing down the down-rev node.
NEO_COUCHSTORE_MANIFEST = {
        "uid": "4",
        "scopes": [{"name": "couchstoreBucketScope",
                    "uid": "8",
                    "collections": [{"name": "couchstoreBucketCollectionTTL123",
                                     "uid": "a",
                                     "maxTTL": 123,
                                     "history": False},
                                    {"name":
                                     "couchstoreBucketCollectionTTLDisabled",
                                     "uid": "9",
                                     "maxTTL": 0,
                                     "history": False},
                                    {"name": "couchstoreBucketCollection",
                                     "uid": "8",
                                     "maxTTL": 0,
                                     "history": False}]},
                   {"name": "_default",
                    "uid": "0",
                    "collections": [{"name": "_default",
                                     "uid": "0",
                                     "maxTTL": 0,
                                     "history": False}]}]}

NEO_EPHEMERAL_MANIFEST = {
        "uid": "4",
        "scopes": [{"name": "ephBucketScope",
                    "uid": "8",
                    "collections": [{"name": "ephBucketCollectionTTL345",
                                     "uid": "a",
                                     "maxTTL": 345,
                                     "history": False},
                                    {"name": "ephBucketCollectionTTLDisabled",
                                     "uid": "9",
                                     "maxTTL": 0,
                                     "history": False},
                                    {"name": "ephBucketCollection",
                                     "uid": "8",
                                     "maxTTL": 0,
                                     "history": False}]},
                   {"name": "_default",
                    "uid": "0",
                    "collections": [{"name": "_default",
                                     "uid": "0",
                                     "maxTTL": 0,
                                     "history": False}]}]}

NEO_MAGMA_MANIFEST = {
        "uid": "5",
        "scopes": [{"name": "magmaBucketScope",
                    "uid": "8",
                    "collections": [{"name": "magmaBucketCollectionTTL888",
                                     "uid": "a",
                                     "maxTTL": 888,
                                     "history": True},
                                    {"name": "magmaBucketCollectionTTLDisabled",
                                     "uid": "9",
                                     "history": True,
                                     "maxTTL": 0},
                                    {"name": "magmaBucketCollection",
                                     "uid": "8",
                                     "history": True,
                                     "maxTTL": 0}]},
                   {"name": "_default",
                    "uid": "0",
                    "collections": [{"name": "_default",
                                     "uid": "0",
                                     "history": True,
                                     "maxTTL": 0}]}]}


class CollectionTests(testlib.BaseTestSet):

    def __init__(self, cluster):
        super().__init__(cluster)

    @staticmethod
    def requirements():
        return testlib.ClusterRequirements(num_nodes=1, memsize=1024)

    def setup(self, cluster):
        # MB-58727 Setup should be able to assume a clean slate when starting
        # and not have to do any housekeeping.
        testlib.delete_all_buckets(cluster)
        # Decrease requirement for magma ram quota
        testlib.post_succ(cluster, "/internalSettings",
                          data={"magmaMinMemoryQuota": 256})

    def teardown(self, cluster):
        pass

    def test_teardown(self, cluster):
        testlib.delete_all_buckets(cluster)

    def create_bucket(self, bucket_name, bucket_type,
                      storage="couchstore"):

        testlib.post_succ(self.cluster, BUCKETS_ENDPOINT,
                          expected_code=202,
                          data={"name": f"{bucket_name}",
                                "bucketType": bucket_type,
                                "storageBackend": storage,
                                "ramQuotaMB": 256})

    # Create the specified bucket and add a scope and collections within
    # the scope. The collections consist of:
    #   * default maxTTL (not provided...use the bucket's maxTTL)
    #   * disabled maxTTL (maxTTL=0)
    #   * maxTTL > 0
    def create_bucket_scopes_collections(self, bucket_name,
                                         bucket_type, storage):
        self.create_bucket(bucket_name, bucket_type, storage)

        scope_url = BUCKETS_ENDPOINT + f"/{bucket_name}/scopes/"
        scope_name = f"{bucket_name}Scope"
        collection_url = scope_url + scope_name + f"/collections/"
        collection_name = f"{bucket_name}Collection"

        testlib.post_succ(self.cluster, scope_url,
                          data={"name": scope_name})
        testlib.post_succ(self.cluster, collection_url,
                          data={"name": f"{collection_name}_maxttl_default"})
        testlib.post_succ(self.cluster, collection_url,
                          data={"name": f"{collection_name}_maxttl_disabled",
                                "maxTTL": 0})
        testlib.post_succ(self.cluster, collection_url,
                          data={"name": f"{collection_name}_maxttl_456",
                                "maxTTL": 456})

    def get_manifest(self, bucket_name):
        r = testlib.get_succ(self.cluster,
                             BUCKETS_ENDPOINT + f"/{bucket_name}/scopes/")
        return r.json()

    # Remove all 'uid' keys from the manifest
    def remove_uid_keys(self, json_obj):
        if isinstance(json_obj, dict):
            # Create a copy of the dictionary to avoid modifying it while
            # iterating.
            json_copy = copy.deepcopy(json_obj)
            for key in json_copy.keys():
                if key == "uid":
                    del json_obj[key]
                else:
                    self.remove_uid_keys(json_obj[key])
        elif isinstance(json_obj, list):
            for item in json_obj:
                self.remove_uid_keys(item)

    # Update the specified collection's maxTTL to be -1. This is the value
    # which backup/restore uses to omit a collection maxTTL.
    def update_maxttl(self, manifest, scope_name, collection_name):
        scopes = manifest.get("scopes")
        for scope in scopes:
            if scope.get("name") == scope_name:
                collections = scope.get("collections", [])
                for collection in collections:
                    if collection.get("name") == collection_name:
                        collection["maxTTL"] = -1

    # Ensure the manifest for a bucket can be applied back to the same
    # bucket.
    def get_put_bucket(self, bucket_name, bucket_type, storage=None):
        self.create_bucket_scopes_collections(bucket_name, bucket_type,
                                              storage)
        manifest = self.get_manifest(bucket_name)
        self.put_manifest(bucket_name, manifest)

    # Restores the manifest to the bucket.
    def put_manifest(self, bucket_name, manifest):
        # Remove 'uid' keys
        self.remove_uid_keys(manifest)
        testlib.put_succ(self.cluster,
                         BUCKETS_ENDPOINT + f"/{bucket_name}/scopes/",
                         headers={"Content-type": "application/json"},
                         json=manifest)

    # Change the collection's maxTTL to the specified value.
    def change_maxttl(self, bucket_name, scope_name, collection_name, value):
        url = BUCKETS_ENDPOINT + f"/{bucket_name}/scopes/" + \
            f"{bucket_name}Scope/collections/{collection_name}"
        testlib.patch_succ(self.cluster, url,
                           data={"maxTTL": value})

    # Create buckets with scope and collections and ensure the manifest
    # which we GET is PUTable.
    def manifest_test(self, cluster):
        # Test the results of GET are PUTable (sans 'uid')
        self.get_put_bucket("couchstoreBucket", "couchbase",
                            "couchstore")
        self.get_put_bucket("magmaBucket", "couchbase", "magma")
        self.get_put_bucket("ephemeralBucket", "ephemeral")

    # Ensure manifests from older release is PUTable.
    def manifest_upgrade_test(self, cluster):
        self.create_bucket("neoCouchstoreBucket", "couchbase", "couchstore")
        self.put_manifest("neoCouchstoreBucket", NEO_COUCHSTORE_MANIFEST)
        self.create_bucket("neoMagmaBucket", "couchbase", "magma")
        self.put_manifest("neoMagmaBucket", NEO_MAGMA_MANIFEST)
        self.create_bucket("neoEphemeralBucket", "ephemeral")
        self.put_manifest("neoEphemeralBucket", NEO_EPHEMERAL_MANIFEST)

    # Verify that maxTTl gets restored to original value after it has
    # been changed to a new value.
    def verify_maxttl_restore_test(self, cluster):
        self.create_bucket_scopes_collections("testBucket", "couchbase",
                                              "couchstore")
        manifest1 = self.get_manifest("testBucket")
        self.remove_uid_keys(manifest1)

        # Change the maxTTL for the collections.
        self.change_maxttl("testBucket", "testBucketScope",
                           "testBucketCollection_maxttl_default", 333)
        self.change_maxttl("testBucket", "testBucketScope",
                           "testBucketCollection_maxttl_disabled", 444)
        self.change_maxttl("testBucket", "testBucketScope",
                           "testBucketCollection_maxttl_456", 555)

        # Ensure the bucket's manifest has changed.
        manifest2 = self.get_manifest("testBucket")
        self.remove_uid_keys(manifest2)
        print(f"Manifest difference is {diff(manifest1, manifest2)}")
        assert manifest2.items() != manifest1.items()

        # Restore the original manifest. Note we make a copy of the original
        # manifest as we have to modify it to mimic restore's use of
        # 'maxTTL=-1' to set the TTL to "use the bucket's maxTTL".
        manifest1_copy = copy.deepcopy(manifest1)
        self.update_maxttl(manifest1_copy, "testBucketScope", 
                           "testBucketCollection_maxttl_default")

        self.put_manifest("testBucket", manifest1_copy)

        # Ensure the manifest matches the original one
        manifest3 = self.get_manifest("testBucket")
        self.remove_uid_keys(manifest3)
        if manifest3.items() != manifest1.items():
            print(f"Unexpected differences {diff(manifest1, manifest3)}")
        assert manifest3.items() == manifest1.items()
