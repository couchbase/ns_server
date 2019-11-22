import uiRouter from "/ui/web_modules/@uirouter/angularjs.js";

import angular from "/ui/web_modules/angular.js";
import mnHelper from "/ui/app/components/mn_helper.js";
import mnPoll from "/ui/app/components/mn_poll.js";

import mnAnalyticsService from "./mn_analytics_service.js";
import mnBucketsService from "./mn_buckets_service.js";
import mnAnalyticsListController from "./mn_analytics_list_controller.js";
import mnAnalyticsListGraphController from "./mn_analytics_list_graph_controller.js";

export default "mnAnalytics";

angular
  .module('mnAnalytics', [mnHelper, mnAnalyticsService, uiRouter, mnPoll])
  .controller('mnAnalyticsController', mnAnalyticsController)
  .controller('mnAnalyticsListController', mnAnalyticsListController)
  .controller('mnAnalyticsListGraphController', mnAnalyticsListGraphController);

function mnAnalyticsController($scope, mnAnalyticsService, $state, mnPoller) {
  var vm = this;

  vm.computeOps = computeOps;
  vm.onSelectBucket = onSelectBucket;
  vm.onSelectNode = onSelectNode;
  vm.currentBucket = $state.params.bucket;

  activate();


  vm.isSpecificStats = !!$state.params.specificStat

  function activate() {
    if (!$state.params.specificStat) {
      new mnPoller($scope, function () {
        return mnAnalyticsService.prepareNodesList($state.params);
      })
        .subscribe("nodes", vm)
        .reloadOnScopeEvent("nodesChanged")
        .cycle();
    }

    //TODO separate dictionary from _uistats
    new mnPoller($scope, function (previousResult) {
      return mnAnalyticsService.getStats({$stateParams: $state.params, previousResult: previousResult});
    })
      .setInterval(function (response) {
        //TODO add error handler
        return response.status ? 10000 : response.stats.nextReqAfter;
      })
      .subscribe("state", vm)
      .reloadOnScopeEvent("reloadAnalyticsPoller");
  }
  function onSelectBucket(selectedBucket) {
    $state.go(vm.isSpecificStats ? '^.specificGraph' : '^.graph', {
      bucket: selectedBucket
    });
  }
  function onSelectNode(selectedHostname) {
    $state.go('^.graph', {
      statsHostname: selectedHostname.indexOf("All Server Nodes") > -1 ? "all" : selectedHostname
    });
  }
  function computeOps(key) {
    return Math.round(key.ops * 100.0) / 100.0;
  }
}
