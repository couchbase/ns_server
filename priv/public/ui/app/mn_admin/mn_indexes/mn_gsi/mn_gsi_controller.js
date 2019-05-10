(function () {
  "use strict";

  angular.module('mnGsi', [
    'mnHelper',
    'mnGsiService',
    'mnSortableTable',
    'mnPoll',
    'mnPoolDefault',
    'mnPermissions',
    'mnSpinner',
    'mnFilters',
    'mnSearch',
    'mnElementCrane',
    'ui.bootstrap',
    'mnPromiseHelper',
    'mnAlertsService','mnAnalyticsService'
  ]).controller('mnGsiController', mnGsiController);

  function mnGsiController($scope, mnGsiService, mnPoller, mnPermissions, mnPoolDefault,mnAnalyticsService) {
    var vm = this;
    vm.focusindexFilter = false;
    vm.currentBucket = mnPermissions.export.bucketNames['.stats!read'] ? mnPermissions.export.bucketNames['.stats!read'][0] : "";
    //vm.onSelectBucket = getPageStats;

    function activate() {
      // quckly get just the names of the indexes
      mnGsiService.getIndexesState(null, false).then(function(res) {vm.state = res;});

      // then poll to get the data at intervals, with index stats
      new mnPoller($scope, function () {
       return mnGsiService.getIndexesState(null, true); // get them with stats
      })
      .setInterval(5000)
      .subscribe("state", vm)
      .reloadOnScopeEvent("indexStatusURIChanged")
      .cycle();
    }

    // done with config
    activate();
  }
})();
