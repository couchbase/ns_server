(function () {
  "use strict";

  angular.module('mnGsiService', [
    "qwQuery"
  ]).factory('mnGsiService', mnGsiServiceFactory);

  function mnGsiServiceFactory($http, qwQueryService) {
    var mnGsiService = {
      getIndexesState: getIndexesState,
      postDropIndex: postDropIndex
    };

    return mnGsiService;

    function postDropIndex(row) {
      // to drop an index, we create a 'DROP' query to send to the query workbench
      return qwQueryService
        .executeQueryUtil('DROP INDEX `' + row.bucket + '`.`' + row.index + '`', true);
    }

    function getIndexesState(mnHttpParams) {
      return $http({
        method: 'GET',
        url: '/indexStatus',
        mnHttp: mnHttpParams
      }).then(function (resp) {
        var byNodes = {};
        var byBucket = {};
        var byID = {};

        function collapsePartition(root, index) {
          if (root[index.id]) {
            root[index.id].partitions = root[index.id].partitions || {};
            if (!root[index.id].partitions[root[index.id].instId]) {
              root[index.id].partitions[root[index.id].instId] =
                Object.assign({}, root[index.id]);
            }
            root[index.id].partitions[index.instId] = Object.assign({}, index);
            root[index.id].hosts = _.uniq(root[index.id].hosts.concat(index.hosts));
          } else {
            root[index.id] = Object.assign({}, index);
          }
        }

        resp.data.indexes.forEach(function (index) {
          collapsePartition(byID, index)

          index.hosts.forEach(function (node) {
            byNodes[node] = byNodes[node] || {};
            collapsePartition(byNodes[node], index);
          });
        });

        Object.keys(byNodes).forEach(function (id) {
          byNodes[id] = Object.values(byNodes[id]);
        });

        Object.keys(byID).forEach(function (id) {
          var index = byID[id];
          byBucket[index.bucket] = byBucket[index.bucket] || [];
          byBucket[index.bucket].push(Object.assign({}, index));
        });

        resp.data.byBucket = byBucket;
        resp.data.byNodes = byNodes;
        resp.data.byID = Object.values(byID);

        return resp.data;
      });
    }
  }
})();
