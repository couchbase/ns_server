/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from 'angular';
import _ from 'lodash';

import mnFilters from './mn_filters.js';
import mnPendingQueryKeeper from './mn_pending_query_keeper.js';

export default 'mnHttp';

angular
  .module('mnHttp', [mnPendingQueryKeeper, mnFilters])
  .factory('mnHttpInterceptor', ["mnPendingQueryKeeper", "$q", "$timeout", "jQueryLikeParamSerializerFilter", "$exceptionHandler", mnHttpFactory])
  .config(["$httpProvider", function ($httpProvider) {
    $httpProvider.interceptors.push('mnHttpInterceptor');
  }]);

function mnHttpFactory(mnPendingQueryKeeper, $q, $timeout, jQueryLikeParamSerializerFilter, $exceptionHandler) {
  var myHttpInterceptor = {
    request: request,
    response: response,
    responseError: responseError
  };

  return myHttpInterceptor;

  function request(config) {
    if (config.url.indexOf(".html") !== -1 || config.doNotIntercept) {
      return config;
    } else {
      return intercept(config);
    }
  }
  function intercept(config) {
    var pendingQuery = {
      config: _.clone(config)
    };
    var mnHttpConfig = config.mnHttp || {};
    delete config.mnHttp;
    if (config.method.toLowerCase() === "post" && mnHttpConfig.cancelPrevious) {
      var queryInFly = mnPendingQueryKeeper.getQueryInFly(config);
      queryInFly && queryInFly.canceler();
    }
    var canceler = $q.defer();
    var timeoutID;
    var timeout = config.timeout;
    var isCleared;

    function clear() {
      if (isCleared) {
        return;
      }
      isCleared = true;
      timeoutID && $timeout.cancel(timeoutID);
      mnPendingQueryKeeper.removeQueryInFly(pendingQuery);
    }

    function cancel(reason) {
      return function () {
        canceler.resolve(reason);
        clear();
      };
    }

    switch (config.method.toLowerCase()) {
    case 'post':
    case 'put':
    case 'patch':
      config.headers = config.headers || {};
      if (!mnHttpConfig.isNotForm) {
        config.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
        if (!angular.isString(config.data)) {
          config.data = jQueryLikeParamSerializerFilter(config.data);
        }
      }
      break;
    }

    config.timeout = canceler.promise;
    config.clear = clear;

    pendingQuery.canceler = cancel("cancelled");
    pendingQuery.group = mnHttpConfig.group;
    mnPendingQueryKeeper.push(pendingQuery);

    if (timeout) {
      timeoutID = $timeout(cancel("timeout"), timeout);
    }
    return config;
  }


  function clearOnResponse(response) {
    if (response.config &&
        response.config.clear && angular.isFunction(response.config.clear)) {
      response.config.clear();
      delete response.config.clear;
    }
  }

  function response(response) {
    clearOnResponse(response);
    return response;
  }
  function responseError(response) {
    if (response instanceof Error) {
      $exceptionHandler(response);
    }
    clearOnResponse(response);
    return $q.reject(response);
  }
}
