/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import axios from 'axios';
import _ from 'lodash';
import mnPendingQueryKeeper from './mn_pending_query_keeper.js';
import jQueryLikeParamSerializerFilter from './mn_filters.js';

axios.interceptors.request.use(request);
axios.interceptors.response.use(response, responseError);

function request(config) {
  if (config.url.indexOf(".html") !== -1 || config.doNotIntercept) {
    return config;
  } else {
    return intercept(config);
  }
}

function intercept(config) {
  const pendingQuery = {
    config: _.clone(config)
  };
  const mnHttpConfig = config.mnHttp || {};
  delete config.mnHttp;

  if (config.method.toLowerCase() === "post" && mnHttpConfig.cancelPrevious) {
    const queryInFly = mnPendingQueryKeeper.getQueryInFly(config);
    queryInFly && queryInFly.canceler();
  }

  const canceler = axios.CancelToken.source();
  let timeoutID;
  const timeout = config.timeout;
  let isCleared;

  function clear() {
    if (isCleared) {
      return;
    }
    isCleared = true;
    timeoutID && clearTimeout(timeoutID);
    mnPendingQueryKeeper.removeQueryInFly(pendingQuery);
  }

  function cancel(reason) {
    return function () {
      canceler.cancel(reason);
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
        if (!_.isString(config.data)) {
          config.data = jQueryLikeParamSerializerFilter(config.data);
        }
      }
      break;
  }

  config.cancelToken = canceler.token;
  config.clear = clear;

  pendingQuery.canceler = cancel("cancelled");
  pendingQuery.group = mnHttpConfig.group;
  mnPendingQueryKeeper.push(pendingQuery);

  if (timeout) {
    timeoutID = setTimeout(cancel("timeout"), timeout);
  }
  return config;
}

function clearOnResponse(response) {
  if (response.config && response.config.clear && _.isFunction(response.config.clear)) {
    response.config.clear();
    delete response.config.clear;
  }
}

function response(response) {
  clearOnResponse(response);
  return response;
}

function responseError(error) {
  if (error instanceof Error) {
    console.error(error);
  }
  clearOnResponse(error.response);
  return Promise.reject(error);
}
