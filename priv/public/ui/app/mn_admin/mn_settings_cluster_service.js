/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from "angular";
import mnPools from "../components/mn_pools.js";
import mnPoolDefault from "../components/mn_pool_default.js";

export default "mnSettingsClusterService";

angular
  .module('mnSettingsClusterService', [mnPools, mnPoolDefault])
  .factory('mnSettingsClusterService', ["$http", "$q", "IEC", "mnPools", "mnPoolDefault", mnSettingsClusterServiceFactory]);

function mnSettingsClusterServiceFactory($http, $q, IEC, mnPools, mnPoolDefault) {
  var mnSettingsClusterService = {
    postPoolsDefault: postPoolsDefault,
    getIndexSettings: getIndexSettings,
    postIndexSettings: postIndexSettings,

    registerInitChecker: registerInitChecker,
    clearInitChecker: clearInitChecker,
    getInitChecker: getInitChecker,

    registerSubmitCallback: registerSubmitCallback,
    clearSubmitCallbacks: clearSubmitCallbacks,
    getSubmitCallbacks: getSubmitCallbacks,

    getSettingsRetryRebalance: getSettingsRetryRebalance,
    postSettingsRetryRebalance: postSettingsRetryRebalance,
    getSettingsRebalance: getSettingsRebalance,
    postSettingsRebalance: postSettingsRebalance,
    getSettingsResource: getSettingsResource,
    postSettingsResource: postSettingsResource,
    getPendingRetryRebalance: getPendingRetryRebalance,
    postCancelRebalanceRetry: postCancelRebalanceRetry,
    getMemcachedSettings: getMemcachedSettings,
    postMemcachedSettings: postMemcachedSettings,
    getSettingsAnalytics: getSettingsAnalytics,
    postSettingsAnalytics: postSettingsAnalytics
  };

  var childSubmitCallbacks = [];
  var childInitChecker = [];

  return mnSettingsClusterService;

  function postSettingsRetryRebalance(data, params) {
    return $http.post("/settings/retryRebalance", data, {params: params});
  }

  function getSettingsRebalance() {
    return $http.get("/settings/rebalance");
  }

  function postSettingsRebalance(data) {
    return $http.post("/settings/rebalance", data);
  }

  function getSettingsResource() {
    return $http.get("/settings/resourceManagement");
  }

  function postSettingsResource(data) {
    return $http.post("/settings/resourceManagement", {"diskUsage.enabled": data.diskUsage.enabled, "diskUsage.maximum": data.diskUsage.maximum});
  }

  function getMemcachedSettings() {
    return $http.get("/pools/default/settings/memcached/global");
  }

  function postMemcachedSettings(data) {
    return $http.post("/pools/default/settings/memcached/global", data);
  }

  function getPendingRetryRebalance(mnHttpParams) {
    return $http({
      url: "/pools/default/pendingRetryRebalance",
      method: 'GET',
      mnHttp: mnHttpParams
    });
  }

  function getSettingsRetryRebalance() {
    return $http.get("/settings/retryRebalance")
      .then(function (resp) {
        return resp.data;
      });
  }

  function postCancelRebalanceRetry(replicationId) {
    return $http({
      url: "/controller/cancelRebalanceRetry/" + encodeURIComponent(replicationId),
      method: "POST",
      mnHttp: {group: "global"}
    });
  }

  function getSettingsAnalytics() {
    return $http.get("/settings/analytics")
      .then(function (resp) {
        return resp.data;
      });
  }

  function postSettingsAnalytics(data) {
    return $http.post("/settings/analytics", data);
  }

  function getInitChecker() {
    return childInitChecker;
  }

  function clearInitChecker() {
    childInitChecker = [];
  }

  function registerInitChecker(cb) {
    childInitChecker.push(cb);
  }

  function getSubmitCallbacks() {
    return childSubmitCallbacks;
  }

  function clearSubmitCallbacks() {
    childSubmitCallbacks = [];
  }

  function registerSubmitCallback(cb) {
    childSubmitCallbacks.push(cb);
  }

  function maybeSetQuota(data, memory, service, key) {
    if (!memory.services || memory.services.model[service]) {
      if (memory[key] === null) {
        data[key] = "";
      } else {
        data[key] = memory[key];
      }
    }
  }

  function postPoolsDefault(memoryQuotaConfig, justValidate, clusterName) {
    var data = {};

    if (clusterName !== undefined) {
      data.clusterName = clusterName;
    }

    if (memoryQuotaConfig) {
      maybeSetQuota(data, memoryQuotaConfig, "kv", "memoryQuota");
      maybeSetQuota(data, memoryQuotaConfig, "index", "indexMemoryQuota");
      maybeSetQuota(data, memoryQuotaConfig, "fts", "ftsMemoryQuota");
      if (mnPools.export.isEnterprise) {
        maybeSetQuota(data, memoryQuotaConfig, "cbas", "cbasMemoryQuota");
        maybeSetQuota(data, memoryQuotaConfig, "eventing", "eventingMemoryQuota");
      }
      if (mnPoolDefault.export.compat.atLeast76) {
        maybeSetQuota(data, memoryQuotaConfig, "n1ql", "queryMemoryQuota");
      }
    }

    var config = {
      method: 'POST',
      url: '/pools/default',
      data: data
    };
    if (justValidate) {
      config.params = {
        just_validate: 1
      };
    }
    return $http(config);
  }
  function getIndexSettings() {
    return $http.get("/settings/indexes").then(function (resp) {
      return resp.data;
    });
  }
  function postIndexSettings(data, justValidate) {
    var configData = {};

    let fields = ["indexerThreads", "logLevel", "maxRollbackPoints", "storageMode"];

    if (mnPoolDefault.export.compat.atLeast70) {
      fields.push("redistributeIndexes");
      fields.push("numReplica");
    }

    if (mnPoolDefault.export.compat.atLeast71) {
      fields.push("enablePageBloomFilter");
    }

    if (mnPoolDefault.export.compat.atLeast76) {
      fields.push("enableShardAffinity");
    }

    fields
      .forEach(function (name) {
        if (data[name] !== undefined) {
          configData[name] = data[name];
        }
      });
    var config = {
      method: 'POST',
      url: '/settings/indexes',
      data: configData
    };
    if (justValidate) {
      config.params = {
        just_validate: 1
      };
    }
    return $http(config);
  }
}
