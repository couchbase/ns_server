import angular from "/ui/web_modules/angular.js";

import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";

import mnPlot from "/ui/app/components/directives/mn_plot.js";
import mnBarUsage from "/ui/app/components/directives/mn_bar_usage/mn_bar_usage.js";
import mnPoll from "/ui/app/components/mn_poll.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnHelper from "/ui/app/components/mn_helper.js";
import mnPoolDefault from "/ui/app/components/mn_pool_default.js";
import mnXDCRService from "./mn_xdcr_service.js";
import mnBucketsService from "./mn_buckets_service.js";
import mnOverviewService from "./mn_overview_service.js";

import mnDropdown from "/ui/app/components/directives/mn_dropdown.js";
import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";

export default 'mnOverview';

angular
  .module('mnOverview', [
    uiBootstrap,
    mnPlot,
    mnBarUsage,
    mnPoll,
    mnPromiseHelper,
    mnHelper,
    mnPoolDefault,
    mnXDCRService,
    mnBucketsService,
    mnOverviewService,
    mnDropdown,
    mnElementCrane
  ])
  .controller('mnOverviewController', mnOverviewController);

function mnOverviewController($scope, $rootScope, mnBucketsService, mnOverviewService, mnPoller, mnPromiseHelper, mnHelper, mnXDCRService, permissions, pools, mnPoolDefault) {
  var vm = this;

  vm.getEndings = mnHelper.getEndings;
  vm.addressFamily = mnPoolDefault.export.thisNode.addressFamily;
  vm.nodeEncryption = mnPoolDefault.export.thisNode.nodeEncryption;

  activate();

  function activate() {
    $rootScope.$broadcast("reloadPoolDefaultPoller");

    if (permissions.cluster.xdcr.remote_clusters.read) {
      new mnPoller($scope, mnXDCRService.getReplicationState)
        .setInterval(3000)
        .subscribe("xdcrReferences", vm)
        .cycle();
    }

    new mnPoller($scope, mnOverviewService.getOverviewConfig)
      .reloadOnScopeEvent("mnPoolDefaultChanged")
      .subscribe("mnOverviewConfig", vm)
      .cycle();
    new mnPoller($scope, function () {
      return mnOverviewService.getServices();
    })
      .reloadOnScopeEvent("nodesChanged")
      .subscribe("nodes", vm)
      .cycle();

    if (permissions.cluster.bucket['.'].stats.read) {
      new mnPoller($scope, mnOverviewService.getStats)
        .setInterval(3000)
        .subscribe("mnOverviewStats", vm)
        .cycle();
    }
  }
}
