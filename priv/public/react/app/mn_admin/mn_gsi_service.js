/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { QwQueryService } from "../_p/ui/query/angular-services/qw.query.service.js";
import mnPoolDefault from "../components/mn_pool_default.js";
import axios from 'axios';

const mnGsiService = {
  getIndexesState,
  getIndexesStateMixed,
  getIndexesStateByNodes,
  getIndexesStateByNodesMixed,
  postDropIndex,
  getIndexStatus
};

export default mnGsiService;

function postDropIndex(row, dropReplicaOnly) {
  // MB-48460 - only need 'default:' for 7.0 and later
  // new indexes have a scope and collection
  let indexIdentifier =
      (mnPoolDefault.export.getValue().compat.atLeast70 ? 'default:' : '') +
      '`' + row.bucket + '`.`' +
      (mnPoolDefault.export.getValue().compat.atLeast70 && row.scope ? row.scope + '`.`' : '') +
      (mnPoolDefault.export.getValue().compat.atLeast70 && row.collection ? row.collection + '`.`' : '') +
      row.indexName + '`';
  // MB-40229 - replica indexes must be removed with ALTER INDEX, others with DROP INDEX
  var query;
  if (row.numReplica > 0 && dropReplicaOnly) {
    query = 'ALTER INDEX ' + indexIdentifier + ' WITH {"action":"drop_replica","replicaId":' + row.replicaId + '};';
  }
  else {
    query = 'DROP INDEX ' + indexIdentifier;
  }

  return QwQueryService
    .executeQueryUtil(query, true);
}

function isKeystoreIndex(index, params) {
  params = params || {};
  return params.bucket &&
    ((params.bucket.name == index.bucket && !index.scope) ||
     (params.bucket.name == index.bucket && params.scope?.name === index.scope));
}

function getIndexStatus(mnHttpParams) {
  return axios.get('/indexStatus', {
    mnHttp: mnHttpParams,
    responseType: 'json'
  }).then(resp => {
    resp.data.indexes.forEach(row => {
      row.keyspace = row.bucket + row.scope + row.collection;
    });
    return resp.data;
  });
}

function getIndexesByNodes(indexes) {
  return indexes.reduce((acc, index) => {
    index.hosts.forEach(node => {
      acc[node] = acc[node] || [];
      acc[node].push(Object.assign({}, index));
    });
    return acc;
  }, {});
}

function filterIndexesByKeystore(indexes, keyStoreParams) {
  return indexes.filter(index => isKeystoreIndex(index, keyStoreParams));
}

function getIndexesStateByNodes(keyStoreParams) {
  return getIndexStatus().then(indexStatus => {
    let indexesToDisplay = filterIndexesByKeystore(indexStatus.indexes, keyStoreParams);
    let byNodes = getIndexesByNodes(indexesToDisplay);
    indexStatus.filtered = indexesToDisplay;
    indexStatus.byNodes = byNodes;
    return indexStatus;
  });
}

function getIndexesState(keyStoreParams) {
  return getIndexStatus().then(indexStatus => {
    let indexesToDisplay = filterIndexesByKeystore(indexStatus.indexes, keyStoreParams);
    indexStatus.filtered = indexesToDisplay;
    return indexStatus;
  });
}

function getIndexesStateByNodesMixed() {
  return getIndexStatus().then(indexStatus => {
    let byNodes = getIndexesByNodes(indexStatus.indexes);
    indexStatus.byNodes = byNodes;
    indexStatus.filtered = indexStatus.indexes;
    return indexStatus;
  });
}

function getIndexesStateMixed() {
  return getIndexStatus().then(indexStatus => {
    indexStatus.filtered = indexStatus.indexes;
    return indexStatus;
  });
}
