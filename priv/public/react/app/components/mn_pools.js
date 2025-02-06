/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import axios from 'axios';
import { BehaviorSubject } from 'rxjs';

const mnPools = {
  get,
  clearCache,
  getFresh,
  export: new BehaviorSubject({}),
};

var cache;
const launchID = new Date().valueOf() + '-' + ((Math.random() * 65536) >> 0);

function get(mnHttpParams) {
  if (cache) {
    return Promise.resolve(cache);
  }

  return axios
    .get('/pools', {
      responseType: 'json',
      mnHttp: mnHttpParams,
    })
    .then((resp) => {
      const pools = resp.data;
      pools.isInitialized = !!pools.pools.length;
      pools.launchID = pools.uuid + '-' + launchID;
      mnPools.export.next(
        Object.assign(structuredClone(mnPools.export.getValue()), pools)
      );
      cache = pools;
      return pools;
    });
}

function clearCache() {
  cache = null;
  return this;
}

function getFresh() {
  return this.clearCache().get();
}

export default mnPools;
