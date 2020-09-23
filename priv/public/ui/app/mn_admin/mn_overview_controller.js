import angular from "/ui/web_modules/angular.js";
import uiRouter from "/ui/web_modules/@uirouter/angularjs.js";
import _ from "/ui/web_modules/lodash.js";

import mnPoll from "/ui/app/components/mn_poll.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnHelper from "/ui/app/components/mn_helper.js";
import mnPoolDefault from "/ui/app/components/mn_pool_default.js";
import mnBucketsService from "./mn_buckets_service.js";
import mnServersService from "./mn_servers_service.js";
import mnStatisticsNew from "./mn_statistics_controller.js";

import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";

export default 'mnOverview';

angular
  .module('mnOverview', [
    uiRouter,
    mnStatisticsNew,
    mnPoll,
    mnPromiseHelper,
    mnHelper,
    mnPoolDefault,
    mnBucketsService,
    mnServersService,
    mnElementCrane
  ])
  .config(mnOverviewConfig)
  .controller('mnOverviewController', mnOverviewController);

function mnOverviewConfig($stateProvider) {
  $stateProvider
    .state('app.admin.overview', {
      url: '/overview',
      abstract: true,
      views: {
        "main@app.admin": {
          controller: 'mnOverviewController as overviewCtl',
          templateUrl: 'app/mn_admin/mn_overview.html'
        }
      },
      data: {
        title: "Dashboard"
      }
    })
    .state('app.admin.overview.statistics', {
      url: '/stats?statsHostname',
      controller: 'mnStatisticsNewController as statisticsNewCtl',
      templateUrl: 'app/mn_admin/mn_statistics.html',
      params: {
        statsHostname: "all"
      },
      redirectTo: function (trans) {
        var mnPermissionsService = trans.injector().get("mnPermissions");
        var params = _.clone(trans.params(), true);
        return mnPermissionsService.check().then(function (permissions) {
          var statsRead = permissions.bucketNames['.stats!read'];
          var state = {state: "app.admin.overview.statistics", params: params};
          if (!params.scenarioBucket && statsRead && statsRead[0]) {
            state.params.scenarioBucket = statsRead[0];
            return state;
          }
          if (params.scenarioBucket &&
              statsRead && statsRead.indexOf(params.scenarioBucket) < 0) {
            state.params.scenarioBucket = statsRead[0];
            return state;
          }
          if (params.scenarioBucket && (!statsRead || !statsRead[0])) {
            state.params.scenarioBucket = null;
            return state;
          }
        });
      }
    });
}


function mnOverviewController($scope, $rootScope, mnBucketsService, mnServersService, mnPoller, mnPromiseHelper, mnHelper, permissions, pools, mnPoolDefault) {
  var vm = this;

  vm.getEndings = mnHelper.getEndings;
  vm.addressFamily = mnPoolDefault.export.thisNode.addressFamily;
  vm.nodeEncryption = mnPoolDefault.export.thisNode.nodeEncryption;

  activate();

  function activate() {
    new mnPoller($scope, function () {
      return mnServersService.getServicesStatus(mnPoolDefault.export.isEnterprise);
    })
      .reloadOnScopeEvent("nodesChanged")
      .subscribe("nodes", vm)
      .cycle();
  }
}
