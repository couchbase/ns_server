import angular from "/ui/web_modules/angular.js";
import { QwQueryService } from "/_p/ui/query/angular-services/qw.query.service.js";
import {downgradeInjectable} from '/ui/web_modules/@angular/upgrade/static.js';
import {MnHelperService} from '/ui/app/mn.helper.service.js';

export default 'mnGsiService';

angular
  .module('mnGsiService', [])
  .factory('qwQueryService', downgradeInjectable(QwQueryService))
  .factory('mnHelperService', downgradeInjectable(MnHelperService))
  .factory('mnGsiService', mnGsiServiceFactory);

function mnGsiServiceFactory($http, qwQueryService) {
  var mnGsiService = {
    getIndexesState: getIndexesState,
    postDropIndex: postDropIndex
  };

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

  function isKeystoreIndex(params, index) {
    return params.bucket &&
      ((params.bucket.name == index.bucket && !index.scope) ||
       (params.bucket.name == index.bucket && params.scope.name === index.scope));
  }

  function getIndexesState(mnHttpParams, params) {
    return $http({
      method: 'GET',
      url: '/indexStatus',
      mnHttp: mnHttpParams
    }).then(function (resp) {
      var byNodes = {};
      var byID = {};
      var indexes = [];

      resp.data.indexes.forEach(function (index) {

        params = params || {};

        index.hosts.forEach(function (node) {
          byNodes[node] = byNodes[node] || [];
          if (isKeystoreIndex(params, index)) {
            byNodes[node].push(Object.assign({}, index));
          }
        });

        if (isKeystoreIndex(params, index)) {
          indexes.push(index);
        }
      });

      resp.data.filtered = indexes;
      resp.data.byNodes = byNodes;
      resp.data.byID = resp.data.indexes;
      return resp.data;
    });
  }
}
