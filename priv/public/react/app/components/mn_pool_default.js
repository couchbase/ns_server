/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import _ from 'lodash';
import axios from 'axios';
import { BehaviorSubject } from 'rxjs';
import mnPools from './mn_pools.js';
import mnHelper from './mn_helper.js';
import { jQueryLikeParamSerializerFilter } from './mn_filters.js';

const mnPoolDefault = {
  latestValue,
  get,
  clearCache,
  getFresh,
  setHideNavSidebar,
  getUrlsRunningService,
  export: new BehaviorSubject({
    compat: undefined,
    hideNavSidebar: false,
  }),
};

let latest = {};
let cache;
let request;

const version50 = encodeCompatVersion(5, 0);
const version51 = encodeCompatVersion(5, 1);
const version55 = encodeCompatVersion(5, 5);
const version65 = encodeCompatVersion(6, 5);
const version66 = encodeCompatVersion(6, 6);
const version70 = encodeCompatVersion(7, 0);
const version71 = encodeCompatVersion(7, 1);
const version72 = encodeCompatVersion(7, 2);
const version75 = encodeCompatVersion(7, 5);
const version76 = encodeCompatVersion(7, 6);
const version764 = encodeCompatVersion(7, 6, 4);
const version80 = encodeCompatVersion(8, 0);

function setHideNavSidebar(value) {
  mnPoolDefault.export.next(
    Object.assign(structuredClone(mnPoolDefault.export.getValue()), {
      hideNavSidebar: value,
    })
  );
}

function latestValue() {
  return latest;
}

function encodeCompatVersion(major, minor) {
  if (major < 2) {
    return 1;
  }
  return major * 0x10000 + minor;
}

function get(params, mnHttpParams) {
  if (!(params && params.etag) && cache) {
    return Promise.resolve(cache);
  }
  if (request && !cache) {
    return request;
  }
  params = params || { waitChange: 0 };
  request = Promise.all([
    axios.get('/pools/default', {
      mnHttp: mnHttpParams,
      params: params,
      timeout: 30000,
    }),
    mnPools.get(mnHttpParams),
  ]).then(
    function (resp) {
      var poolDefault = resp[0].data;
      var pools = resp[1];
      poolDefault.rebalancing = poolDefault.rebalanceStatus !== 'none';
      poolDefault.isGroupsAvailable = !!(
        pools.isEnterprise && poolDefault.serverGroupsUri
      );
      poolDefault.isEnterprise = pools.isEnterprise;
      poolDefault.thisNode = _.find(poolDefault.nodes, function (n) {
        return n.thisNode;
      });

      poolDefault.isStrippingPort = poolDefault.nodes.every((node) =>
        node.hostname.includes(':8091')
      );

      poolDefault.compat = {
        atLeast51: poolDefault.thisNode.clusterCompatibility >= version51,
        atLeast55: poolDefault.thisNode.clusterCompatibility >= version55,
        atLeast65: poolDefault.thisNode.clusterCompatibility >= version65,
        atLeast66: poolDefault.thisNode.clusterCompatibility >= version66,
        atLeast70: poolDefault.thisNode.clusterCompatibility >= version70,
        atLeast71: poolDefault.thisNode.clusterCompatibility >= version71,
        atLeast72: poolDefault.thisNode.clusterCompatibility >= version72,
        atLeast75: poolDefault.thisNode.clusterCompatibility >= version75,
        atLeast76: poolDefault.thisNode.clusterCompatibility >= version76,
        atLeast764: poolDefault.thisNode.clusterCompatibility >= version764,
        atLeast80: poolDefault.thisNode.clusterCompatibility >= version80,
      };
      poolDefault.versions = {
        50: version50,
        51: version51,
        55: version55,
        65: version65,
        66: version66,
        70: version70,
        71: version71,
        72: version72,
        75: version75,
        76: version76,
        764: version764,
        80: version80,
      };
      poolDefault.capiBase =
        window.location.protocol === 'https:'
          ? poolDefault.thisNode.couchApiBaseHTTPS
          : poolDefault.thisNode.couchApiBase;

      mnPoolDefault.export.next(
        Object.assign(
          structuredClone(mnPoolDefault.export.getValue()),
          poolDefault
        )
      );
      latest.value = poolDefault; // deprecated and superseded by mnPoolDefault.export
      cache = poolDefault;

      return poolDefault;
    },
    function (resp) {
      if (
        (resp.status === 404 && resp.data === 'unknown pool') ||
        resp.status === 500
      ) {
        mnHelper.reloadApp();
      }
      return Promise.reject(resp);
    }
  );
  return request;
}

function clearCache() {
  cache = undefined;
  request = undefined;
  return this;
}

function getFresh(params) {
  return mnPoolDefault.clearCache().get(params);
}

function parseHostname(href) {
  var l = document.createElement('a');
  l.href = href;
  return l;
}

function getUrlsRunningService(nodeInfos, service, max) {
  var nodes = _.filter(nodeInfos, function (node) {
    return (
      _.indexOf(node.services, service) > -1 &&
      node.clusterMembership === 'active'
    );
  });
  if (max && max < nodes.length) {
    nodes = nodes.slice(0, max);
  }
  var protocol = window.location.protocol.slice(0, -1);
  var search = jQueryLikeParamSerializerFilter(window.location.search);
  var hash = window.location.hash;
  var ext =
    // it seems like getUrlsRunningService function is not used.
    // should be ok to remove this code later

    // UIRouter.stateService.transition ? parseHostname(
    //   $state.href(
    //     $state.transition.to().name,
    //     $state.transition.params("to"),
    //     { absolute: true }
    //   )
    // ).hash :
    '#!' +
    window.location.pathname +
    (search ? '?' + search : '') +
    (hash ? '#' + hash : '');

  return _.map(nodes, function (node) {
    var link = parseHostname('http://' + node.hostname);
    var port = protocol == 'https' ? node.ports.httpsMgmt : link.port;
    return (
      protocol +
      '://' +
      link.hostname +
      ':' +
      port +
      window.location.pathname +
      ext
    );
  });
}

export default mnPoolDefault;
