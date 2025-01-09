/*
Copyright 2016-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from 'angular';
import _ from 'lodash';
import {BehaviorSubject} from 'rxjs';

import mnBucketsService from '../mn_admin/mn_buckets_service.js';

export default "mnPermissions";

angular
  .module("mnPermissions", [mnBucketsService])
  .provider("mnPermissions", mnPermissionsProvider);

function mnPermissionsProvider() {
  this.$get = ["$http", "$timeout", "$q", "$rootScope", "mnBucketsService", "$parse", mnPermissionsFacatory];
  this.set = set;
  this.setBucketSpecific = setBucketSpecific;

  var bucketSpecificPermissions = [function (name, buckets) {
    var basePermissions = [
      "cluster.bucket[" + name + "].settings!write",
      "cluster.bucket[" + name + "].settings!read",
      "cluster.bucket[" + name + "].recovery!write",
      "cluster.bucket[" + name + "].recovery!read",
      "cluster.bucket[" + name + "].stats!read",
      "cluster.bucket[" + name + "]!flush",
      "cluster.bucket[" + name + "]!delete",
      "cluster.bucket[" + name + "]!compact",
      "cluster.bucket[" + name + "].xdcr!read",
      "cluster.bucket[" + name + "].xdcr!write",
      "cluster.bucket[" + name + "].xdcr!execute",
      "cluster.bucket[" + name + "].n1ql.select!execute",
      "cluster.bucket[" + name + "].n1ql.index!read",
      "cluster.bucket[" + name + "].n1ql.index!write",
      "cluster.bucket[" + name + "].collections!read",
      "cluster.bucket[" + name + "].collections!write",
      "cluster.collection[" + name + ":.:.].stats!read",
      "cluster.collection[" + name + ":.:.].collections!read",
      "cluster.collection[" + name + ":.:.].collections!write"
    ];
    if (name === "." || buckets.byName[name].isMembase) {
      basePermissions = basePermissions.concat([
        "cluster.bucket[" + name + "].views!read",
        "cluster.bucket[" + name + "].views!write",
        "cluster.bucket[" + name + "].views!compact"
      ]);
    }
    if (name === "." || !buckets.byName[name].isMemcached) {
      basePermissions = basePermissions.concat([
        "cluster.bucket[" + name + "].data!write",
        "cluster.bucket[" + name + "].data!read",
        "cluster.bucket[" + name + "].data.docs!read",
        "cluster.bucket[" + name + "].data.docs!write",
        "cluster.bucket[" + name + "].data.docs!upsert",
        "cluster.bucket[" + name + "].n1ql.index!read",
        "cluster.collection[" + name + ":.:.].data.docs!read",
        "cluster.collection[" + name + ":.:.].data.docs!write",
        "cluster.collection[" + name + ":.:.].data.docs!upsert",
        "cluster.collection[" + name + ":.:.].n1ql.index!read",
        "cluster.collection[" + name + ":.:.].n1ql.index!write",
        "cluster.collection[" + name + ":.:.].n1ql.select!execute"
      ]);
    }

    return basePermissions
  }];

  var interestingPermissions = [
    "cluster.buckets!create",
    "cluster.backup!read",
    "cluster.nodes!write",
    "cluster.pools!read",
    "cluster.server_groups!read",
    "cluster.server_groups!write",
    "cluster.settings!read",
    "cluster.settings!write",
    "cluster.settings.metrics!read",
    "cluster.settings.metrics!write",
    "cluster.stats!read",
    "cluster.tasks!read",
    "cluster.settings.indexes!read",
    "cluster.admin.internal!all",
    "cluster.xdcr.settings!read",
    "cluster.xdcr.settings!write",
    "cluster.xdcr.remote_clusters!read",
    "cluster.xdcr.remote_clusters!write",
    "cluster.admin.security!read",
    "cluster.admin.logs!read",
    "cluster.admin.settings!read",
    "cluster.admin.settings!write",
    "cluster.logs!read",
    "cluster.pools!write",
    "cluster.settings.indexes!write",
    "cluster.admin.security!write",
    "cluster.admin.security.admin!write",
    "cluster.admin.security.admin!read",
    "cluster.admin.security.external!write",
    "cluster.admin.security.external!read",
    "cluster.admin.security.local!read",
    "cluster.admin.security.local!write",
    "cluster.admin.users!read",
    "cluster.admin.users!write",
    "cluster.admin.users.local!read",
    "cluster.admin.users.local!write",
    "cluster.admin.users.external!read",
    "cluster.admin.users.external!write",
    "cluster.samples!read",
    "cluster.nodes!read",
    "cluster.admin.memcached!read",
    "cluster.admin.memcached!write",
    "cluster.eventing.functions!manage",
    "cluster.settings.autocompaction!read",
    "cluster.settings.autocompaction!write"
  ];

  function getAll() {
    return _.clone(interestingPermissions);
  }

  function set(permission) {
    if (!_.contains(interestingPermissions, permission)) {
      interestingPermissions.push(permission);
    }
    return this;
  }

  function remove(permission) {
    let index = interestingPermissions.indexOf(permission);
    if (index > 0) {
      interestingPermissions.splice(index, 1);
    }
    return this;
  }

  function setBucketSpecific(func) {
    if (angular.isFunction(func)) {
      bucketSpecificPermissions.push(func);
    }
    return this;
  }

  function generateBucketPermissions(bucketName, buckets) {
    return bucketSpecificPermissions.reduce(function (acc, getChunk) {
      return acc.concat(getChunk(bucketName, buckets));
    }, []);
  }

  function mnPermissionsFacatory($http, $timeout, $q, $rootScope, mnBucketsService, $parse) {
    var mnPermissions = {
      clear: clear,
      get: doCheck,
      check: check,
      set: set,
      stream: new BehaviorSubject(),
      remove: remove,
      throttledCheck: _.debounce(getFresh, 200),
      getFresh: getFresh,
      getBucketPermissions: getBucketPermissions,
      getPerScopePermissions: getPerScopePermissions,
      getPerCollectionPermissions: getPerCollectionPermissions,
      export: {
        data: {},
        cluster: {},
        default: {
          all: undefined,
          membase: undefined
        }
      }
    };

    var cache;

    interestingPermissions.push(generateBucketPermissions("."));

    return mnPermissions;

    function getPerScopePermissions(bucketName, scopeName) {
      let any = bucketName + ":" + scopeName + ":.";
      let all = bucketName + ":" + scopeName + ":*"
      return ["cluster.collection[" + any + "].data.docs!read",
              "cluster.collection[" + all + "].collections!write",
              "cluster.collection[" + any + "].n1ql.select!execute"];
    }
    function getPerCollectionPermissions(bucketName, scopeName, collectionName) {
      let params = bucketName + ":" + scopeName + ":" + collectionName;
      return ["cluster.collection[" + params + "].data.docs!read",
              "cluster.collection[" + params + "].n1ql.select!execute"];
    }

    function clear() {
      delete $rootScope.rbac;
      mnPermissions.export.cluster = {};
      mnPermissions.export.data = {};
      clearCache();
    }

    function clearCache() {
      cache = null;
    }

    function getFresh() {
      clearCache();
      return mnPermissions.check();
    }

    function getBucketPermissions(bucketName) {
      return mnBucketsService.getBucketsByType().then(function (bucketsDetails) {
        return generateBucketPermissions(bucketName, bucketsDetails);
      });
    }

    function check() {
      if (cache) {
        return $q.when(mnPermissions.export);
      }

      return doCheck(["cluster.bucket[.].settings!read"]).then(function (resp) {
        var permissions = getAll();
        if (resp.data["cluster.bucket[.].settings!read"]) {
          return mnBucketsService.getBucketsByType().then(function (bucketsDetails) {
            if (bucketsDetails.length) {
              angular.forEach(bucketsDetails, function (bucket) {
                permissions = permissions.concat(generateBucketPermissions(bucket.name, bucketsDetails));
              });
            }
            return doCheck(permissions).then(function (resp) {
              var bucketNamesByPermission = {};
              var bucketCollectionsNames = {};
              var permissions = resp.data;
              angular.forEach(bucketsDetails, function (bucket) {
                var interesting = generateBucketPermissions(bucket.name, bucketsDetails);
                angular.forEach(interesting, function (permission) {
                  var bucketPermission = permission.split("[" + bucket.name + "]")[1];
                  var collectionPermission = permission.split("[" + bucket.name + ":.:.]")[1];

                  bucketNamesByPermission[bucketPermission] =
                    bucketNamesByPermission[bucketPermission] || [];

                  bucketCollectionsNames[collectionPermission] =
                    bucketCollectionsNames[collectionPermission] || [];

                  if (bucketPermission && permissions[permission]) {
                    bucketNamesByPermission[bucketPermission].push(bucket.name);
                  }

                  if (collectionPermission && permissions[permission]) {
                    bucketCollectionsNames[collectionPermission].push(bucket.name);
                  }
                });
              });
              resp.bucketNames = bucketNamesByPermission;
              resp.bucketCollectionsNames = bucketCollectionsNames;
              return resp;
            });
          });
        } else {
          return doCheck(permissions);
        }
      }).then(function (resp) {
        cache = convertIntoTree(resp.data);

        mnPermissions.export.data = resp.data;
        mnPermissions.export.cluster = cache.cluster;
        mnPermissions.export.bucketNames = resp.bucketNames || {};
        mnPermissions.export.bucketCollectionsNames = resp.bucketCollectionsNames || {};

        mnPermissions.stream.next(mnPermissions.export);

        return mnPermissions.export;
      });
    }

    function convertIntoTree(permissions) {
      var rv = {};
      angular.forEach(permissions, function (value, key) {
        var levels = key.split(/[[\]]+/);
        var regex = /[.:!]+/;
        if (levels[1]) {
          levels = _.compact(levels[0].split(regex).concat([levels[1]]).concat(levels[2].split(regex)))
        } else {
          levels = levels[0].split(regex);
        }
        var path = levels.shift() + "['" + levels.join("']['") + "']"; //in order to properly handle bucket names
        $parse(path).assign(rv, value);
      });
      return rv;
    }

    function doCheck(interestingPermissions) {
      return $http({
        method: "POST",
        url: "/pools/default/checkPermissions",
        data: interestingPermissions.join(',')
      });
    }
  }
}
