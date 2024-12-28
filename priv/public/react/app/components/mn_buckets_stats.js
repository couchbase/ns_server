/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import axios from 'axios';

var mnBucketsStats = {
  get: get,
  clearCache: clearCache,
};

export default mnBucketsStats;

var cache;

function get(mnHttpParams) {
  if (cache) {
    return Promise.resolve(cache);
  }
  return axios.get('/pools/default/buckets?basic_stats=true&skipMap=true', {
    mnHttp: mnHttpParams
  }).then(response => {
    cache = response;
    return response;
  });
}

function clearCache() {
  cache = null;
  return this;
}
