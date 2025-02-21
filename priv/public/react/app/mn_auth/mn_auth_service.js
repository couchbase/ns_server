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
import mnPools from '../components/mn_pools.js';

// Cache for whoami requests
var whoamiCache;

var mnAuthService = {
  login: login,
  logout: _.once(logout),
  whoami: whoami,
  canUseCertForAuth: canUseCertForAuth,
};

function whoami() {
  if (whoamiCache) {
    return Promise.resolve(whoamiCache);
  }
  return axios.get('/whoami').then(function (resp) {
    whoamiCache = resp.data;
    return resp.data;
  });
}

function canUseCertForAuth() {
  return axios.get('/_ui/canUseCertForAuth').then(function (r) {
    return r.data;
  });
}

function login(user, useCertForAuth) {
  var config = {
    url: '/uilogin',
    method: 'POST',
  };

  if (useCertForAuth) {
    config.params = {
      use_cert_for_auth: 1,
    };
  } else {
    user = user || {};
    config.data = {
      user: user.username,
      password: user.password,
    };
  }

  return axios(config).then(function (resp) {
    return mnPools
      .get()
      .then(function (cachedPools) {
        mnPools.clearCache();
        return mnPools.get().then(function (newPools) {
          if (
            cachedPools.implementationVersion !== newPools.implementationVersion
          ) {
            return Promise.reject({ status: 410 });
          } else {
            return resp;
          }
        });
      })
      .then(function (resp) {
        localStorage.setItem(
          'mnLogIn',
          Number(localStorage.getItem('mnLogIn') || '0') + 1
        );
        return resp;
      });
  });
}

function logout() {
  // Note: $uibModalStack.dismissAll is replaced by the modal context in components that use this service
  return axios.post('/uilogout').then(
    function () {
      window.location.reload();
    },
    function (response) {
      let maybeRedirect = response?.data?.redirect;
      if (response.status === 400 && maybeRedirect) {
        window.location.href = maybeRedirect;
      } else {
        window.location.reload();
      }
    }
  );
}

export default mnAuthService;
