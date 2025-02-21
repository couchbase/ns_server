/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import axios from 'axios';

var mnSettingsAutoFailoverService = {
  resetAutoFailOverCount: resetAutoFailOverCount,
  resetAutoReprovisionCount: resetAutoReprovisionCount,
  getAutoFailoverSettings: getAutoFailoverSettings,
  saveAutoFailoverSettings: saveAutoFailoverSettings,
  getAutoReprovisionSettings: getAutoReprovisionSettings,
  postAutoReprovisionSettings: postAutoReprovisionSettings,
};

function resetAutoFailOverCount(mnHttpParams) {
  return axios({
    method: 'POST',
    url: '/settings/autoFailover/resetCount',
    mnHttp: mnHttpParams,
  });
}

function getAutoFailoverSettings() {
  return axios.get('/settings/autoFailover').then(function (resp) {
    return resp.data;
  });
}

function saveAutoFailoverSettings(autoFailoverSettings, params) {
  return axios({
    method: 'POST',
    url: '/settings/autoFailover',
    data: autoFailoverSettings,
    params: params,
  });
}

function getAutoReprovisionSettings() {
  return axios({
    method: 'GET',
    url: '/settings/autoReprovision',
  });
}

function postAutoReprovisionSettings(settings, params) {
  return axios({
    method: 'POST',
    url: '/settings/autoReprovision',
    data: settings,
    params: params,
  });
}

function resetAutoReprovisionCount(mnHttpParams) {
  return axios({
    method: 'POST',
    url: '/settings/autoReprovision/resetCount',
    mnHttp: mnHttpParams,
  });
}

export default mnSettingsAutoFailoverService;
