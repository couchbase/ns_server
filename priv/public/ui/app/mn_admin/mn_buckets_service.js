import angular from "/ui/web_modules/angular.js";
import _ from "/ui/web_modules/lodash.js";

import mnBucketsStats from "/ui/app/components/mn_buckets_stats.js";

export default "mnBucketsService";

angular
  .module('mnBucketsService', [mnBucketsStats])
  .factory('mnBucketsService', mnBucketsServiceFactory);

function mnBucketsServiceFactory($q, mnBucketsStats) {
  var mnBucketsService = {
    getBucketsByType: getBucketsByType,
    clearCache: clearCache,
    findMoxiBucket: findMoxiBucket,
    export: {}
  };
  var cache;

  return mnBucketsService;

  function clearCache() {
    mnBucketsStats.clearCache();
    cache = null
  }

  function findMoxiBucket(mnHttpParams) {
    return mnBucketsStats.get(mnHttpParams).then(function (resp) {
      return _.find(resp.data, function (bucket) {
        return bucket.proxyPort > 0;
      });
    });
  }

  function getBucketsByType(mnHttpParams) {
    if (!!cache) {
      return $q.when(cache);
    }
    return mnBucketsStats.get(mnHttpParams).then(function (resp) {
      var bucketsDetails = resp.data;
      bucketsDetails.byType = {membase: [], memcached: [], ephemeral: []};
      bucketsDetails.byName = {};
      bucketsDetails.byType.membase.isMembase = true;
      bucketsDetails.byType.memcached.isMemcached = true;
      bucketsDetails.byType.ephemeral.isEphemeral = true;
      _.each(bucketsDetails, function (bucket) {
        bucketsDetails.byName[bucket.name] = bucket;
        bucketsDetails.byType[bucket.bucketType].push(bucket);
        bucket.isMembase = bucket.bucketType === 'membase';
        bucket.isEphemeral = bucket.bucketType === 'ephemeral';
        bucket.isMemcached = bucket.bucketType === 'memcached';
      });
      bucketsDetails.byType.names = _.pluck(bucketsDetails, 'name');

      cache = bucketsDetails;
      mnBucketsService.export.details = bucketsDetails;
      return bucketsDetails;
    });
  }
}
