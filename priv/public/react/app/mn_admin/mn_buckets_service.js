/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import _ from "lodash";
import mnBucketsStats from "../components/mn_buckets_stats.js";
import { BehaviorSubject } from "rxjs";

const mnBucketsService = {
  getBucketsByType,
  clearCache,
  findMoxiBucket,
  export: new BehaviorSubject({})
};
let cache;

export default mnBucketsService;

function clearCache() {
  mnBucketsStats.clearCache();
  cache = null;
}

function findMoxiBucket(mnHttpParams) {
  return mnBucketsStats.get(mnHttpParams).then(function (resp) {
    return _.find(resp.data, function (bucket) {
      return bucket.proxyPort > 0;
    });
  });
}

function getBucketsByType(mnHttpParams) {
  if (cache) {
    return Promise.resolve(cache);
  }
  return mnBucketsStats.get(mnHttpParams).then(function (resp) {
    var bucketsDetails = resp.data;
    // TODO: remove memcached type once backend no longer supports them
    bucketsDetails.byType = {membase: [], memcached: [], ephemeral: []};
    bucketsDetails.byName = {};
    bucketsDetails.byType.membase.isMembase = true;
    bucketsDetails.byType.ephemeral.isEphemeral = true;
    _.each(bucketsDetails, function (bucket) {
      bucketsDetails.byName[bucket.name] = bucket;
      bucketsDetails.byType[bucket.bucketType].push(bucket);
      bucket.isMembase = bucket.bucketType === 'membase';
      bucket.isEphemeral = bucket.bucketType === 'ephemeral';
    });
    bucketsDetails.byType.names = _.pluck(bucketsDetails, 'name');

    cache = bucketsDetails;
    mnBucketsService.export.next({details: bucketsDetails});
    return bucketsDetails;
  });
}
