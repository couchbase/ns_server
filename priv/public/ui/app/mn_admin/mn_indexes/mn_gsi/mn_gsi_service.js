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
        resp.data.groups = _.groupBy(resp.data.indexes, 'bucket');
        resp.data.nodes = _.groupBy(resp.data.indexes, function (index) {
          return index.hosts.join(", ");
        });
        return resp.data;
      });
    }
  }
})();
