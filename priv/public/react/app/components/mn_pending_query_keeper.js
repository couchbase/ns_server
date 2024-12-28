/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import _ from 'lodash';

const mnPendingQueryKeeper = {
  getQueryInFly,
  removeQueryInFly,
  push,
  cancelTabsSpecificQueries,
  cancelAllQueries
};

const pendingQueryKeeper = [];

function cancelAllQueries() {
  let i = pendingQueryKeeper.length;
  while (i--) {
    pendingQueryKeeper[i].canceler();
  }
}

function cancelTabsSpecificQueries() {
  let i = pendingQueryKeeper.length;
  while (i--) {
    if (pendingQueryKeeper[i].group !== "global") {
      pendingQueryKeeper[i].canceler();
    }
  }
}

function removeQueryInFly(findMe) {
  let i = pendingQueryKeeper.length;
  while (i--) {
    if (pendingQueryKeeper[i] === findMe) {
      pendingQueryKeeper.splice(i, 1);
    }
  }
}

function getQueryInFly(config) {
  return _.find(pendingQueryKeeper, function (inFly) {
    return inFly.config.method === config.method &&
      inFly.config.url === config.url;
  });
}

function push(query) {
  pendingQueryKeeper.push(query);
}

export default mnPendingQueryKeeper;
