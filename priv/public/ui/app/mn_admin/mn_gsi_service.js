import angular from "/ui/web_modules/angular.js";
import { QwQueryService } from "/_p/ui/query/angular-services/qw.query.service.js";
import {downgradeInjectable} from '/ui/web_modules/@angular/upgrade/static.js';
import {MnHelperService} from '/ui/app/mn.helper.service.js';
import mnStatisticsNewService from '/ui/app/mn_admin/mn_statistics_service.js';
import mnPoolDefault from "/ui/app/components/mn_pool_default.js";
import mnStatisticsDescription from "./mn_statistics_description.js";

export default 'mnGsiService';

angular
  .module('mnGsiService', [mnStatisticsNewService, mnPoolDefault])
  .factory('qwQueryService', downgradeInjectable(QwQueryService))
  .factory('mnHelperService', downgradeInjectable(MnHelperService))
  .factory('mnGsiService', mnGsiServiceFactory);

function mnGsiServiceFactory($http, $q, qwQueryService, mnStatisticsNewService, mnPoolDefault) {
  var mnGsiService = {
    getIndexesState: getIndexesState,
    getIndexesStateMixed: getIndexesStateMixed,
    getIndexesStateByNodes: getIndexesStateByNodes,
    getIndexesStateByNodesMixed: getIndexesStateByNodesMixed,
    postDropIndex: postDropIndex,
    getIndexStatus: getIndexStatus
  };

  let isAtLeast70 = mnPoolDefault.export.compat.atLeast70;

  let perItemStats = [
    "@index-.@items.index_num_requests", "@index-.@items.index_resident_percent",
    "@index-.@items.index_items_count", "@index-.@items.index_data_size",
    "@index-.@items.index_num_docs_pending_and_queued"
  ];

  //should be the same name for mixed version as well
  let uiStatNames = perItemStats.map(
    stat => mnStatisticsDescription.mapping70(stat).split(".").pop());

  if (!isAtLeast70) {
    perItemStats = perItemStats.map(mnStatisticsDescription.mapping70);
  }

  return mnGsiService;

  function postDropIndex(row) {
    // new indexes have a scope and collection
    var query = 'DROP INDEX default:`' + row.bucket + '`.`' +
        (row.scope ? row.scope + '`.`' : '') +
        (row.collection ? row.collection + '`.`' : '') +
        row.indexName + '`';

    return qwQueryService
      .executeQueryUtil(query, true);
  }

  function isKeystoreIndex(index, params) {
    params = params || {};
    return params.bucket &&
      ((params.bucket.name == index.bucket && !index.scope) ||
       (params.bucket.name == index.bucket && params.scope.name === index.scope));
  }

  function getIndexStatus(mnHttpParams) {
    return $http({
      method: 'GET',
      url: '/indexStatus',
      mnHttp: mnHttpParams
    }).then(resp => {
      resp.data.indexes.forEach(row => {
        row.keyspace = row.bucket + row.scope + row.collection;
      });
      return resp.data;
    });
  }

  function getIndexStatsConfig(index, node) {
    return {
      bucket: index.bucket,
      scope: index.scope,
      collection: index.collection,
      node: node || "all",
      zoom: 3000,
      step: 1,
      stats: perItemStats,
      items: {
        index: isAtLeast70 ?
          index.index : ("index/" + index.index + "/")
      }
    };
  }

  function getIndexStatsConfigs(indexes, node) {
    return indexes.reduce((acc, index) => {
      let cfg = getIndexStatsConfig(index, node);
      let configs = mnStatisticsNewService.packStatsConfig(cfg, true);
      Array.prototype.push.apply(acc, configs);
      return acc;
    }, []);
  }

  function getIndexStatsConfigsByNode(byNode) {
    return Object.keys(byNode).reduce((acc, node) => {
      let configs = getIndexStatsConfigs(byNode[node], node);
      Array.prototype.push.apply(acc, configs);
      return configs;
    }, []);
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
      let statsConfigs = getIndexStatsConfigsByNode(byNodes);
      indexStatus.filtered = indexesToDisplay;
      indexStatus.byNodes = byNodes;
      return $q.all([
        mnStatisticsNewService.postStatsRange(statsConfigs), $q.when(indexStatus)
      ]).then(([perIndexStats, indexStatus]) => {
        let nodes = Object.keys(indexStatus.byNodes);
        let checkpoint = 0;

        nodes.forEach(node => {
          let indexes = indexStatus.byNodes[node];
          let nextCheckpoint = checkpoint + (indexes.length * perItemStats.length);
          let thisNodeStats = perIndexStats.data.slice(checkpoint, nextCheckpoint);
          checkpoint = nextCheckpoint;

          indexes.forEach((row, i) => {
            let start = i * perItemStats.length;
            let end = start + perItemStats.length;
            let stats = thisNodeStats.slice(start, end);

            uiStatNames.forEach((statName, i) => {
              row[statName] = stats[i].data[0] ? Number(stats[i].data[0].values[0][1]) : null;
            });
          });
        });
        return indexStatus;
      });
    });
  }

  function getIndexesState(keyStoreParams) {
    return getIndexStatus().then(indexStatus => {
      let indexesToDisplay = filterIndexesByKeystore(indexStatus.indexes, keyStoreParams);
      let statsConfigs = getIndexStatsConfigs(indexesToDisplay);
      indexStatus.filtered = indexesToDisplay;
      return $q.all([
        mnStatisticsNewService.postStatsRange(statsConfigs), $q.when(indexStatus)
      ]).then(([perIndexStats, indexStatus]) => {
        indexStatus.filtered.forEach((row, i) => {
          let start = i * perItemStats.length;
          let end = start + perItemStats.length;
          let stats = perIndexStats.data.slice(start, end);

          uiStatNames.forEach((statName, i) => {
            row[statName] = stats[i].data[0] ? Number(stats[i].data[0].values[0][1]) : null
          });
        });
        return indexStatus;
      });
    });
  }

  function getIndexesStateByNodesMixed() {
    return getIndexStatus().then(indexStatus => {
      let byNodes = getIndexesByNodes(indexStatus.indexes);
      let statsConfigs = getIndexStatsConfigsByNode(byNodes);
      indexStatus.byNodes = byNodes;
      indexStatus.filtered = indexStatus.indexes;

      return $q.all([
        mnStatisticsNewService.postStats(statsConfigs), $q.when(indexStatus)
      ]).then(([perIndexStats, indexStatus]) => {
        let nodes = Object.keys(indexStatus.byNodes);
        let checkpoint = 0;

        nodes.forEach(node => {
          let indexes = indexStatus.byNodes[node];
          let nextCheckpoint = checkpoint + indexes.length;
          let thisNodeStats = perIndexStats.data.slice(checkpoint, nextCheckpoint);
          checkpoint = nextCheckpoint;

          indexes.forEach((row, indexI) => {
            uiStatNames.forEach((statName, i) => {
              let stats = perIndexStats.data[indexI].stats["index/"+row.index+"/"+statName];
              row[statName] = stats[node] ? stats[node][0] : null
            });
          });
        });

        return indexStatus;
      });
    });
  }

  function getIndexesStateMixed() {
    return getIndexStatus().then(indexStatus => {
      let statsConfigs = getIndexStatsConfigs(indexStatus.indexes);
      indexStatus.filtered = indexStatus.indexes;
      return $q.all([
        mnStatisticsNewService.postStats(statsConfigs), $q.when(indexStatus)
      ]).then(([perIndexStats, indexStatus]) => {
        indexStatus.filtered.forEach((row, indexI) => {
          uiStatNames.forEach((statName, i) => {
            let stats = perIndexStats.data[indexI].stats["index/"+row.index+"/"+statName];
            row[statName] = stats.aggregate ? stats.aggregate[0] : null
          });
        });
        return indexStatus;
      });
    });
  }
}
