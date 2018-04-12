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
        resp.data.indexes.forEach(function (index) {
          byBucket[index.bucket] = byBucket[index.bucket] || [];
          byBucket[index.bucket].push(_.clone(index));

          index.hosts.forEach(function (node) {
            byNodes[node] = byNodes[node] || [];
            byNodes[node].push(_.clone(index));
          });
        });
        resp.data.groups = byBucket;
        resp.data.nodes = byNodes;
        return resp.data;
      });
    }
  }
})();
