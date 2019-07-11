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
    'mnAlertsService',
    'mnStatisticsNewService'
  ]).controller('mnGsiController', mnGsiController)
    .controller('mnGsiStatsController', mnGsiStatsController);

  function mnGsiController($scope, mnGsiService, mnPoller) {
    var vm = this;
    activate();

    function activate() {
      new mnPoller($scope, function () {
        return mnGsiService.getIndexesState();
      })
        .setInterval(10000)
        .subscribe("state", vm)
        .reloadOnScopeEvent("indexStatusURIChanged")
        .cycle();
    }
  }

  function mnGsiStatsController($scope, mnStatisticsNewService, mnPoller, mnPermissions) {
    var vm = this;
    vm.currentBucket = mnPermissions.export.bucketNames['.stats!read'][0];
    vm.onSelectBucket = onSelectBucket;

    activate();

    function activate() {
      new mnPoller($scope, function (previousResult) {
        return mnStatisticsNewService.doGetStats({
          zoom: "minute",
          bucket: vm.currentBucket,
          node: "all"
        }, previousResult);
      })
        .setInterval(5000)
        .subscribe(getAverageUIStats)
        .reloadOnScopeEvent("reloadUIStatPoller")
        .cycle();
    }

    function onSelectBucket() {
      $scope.$broadcast("reloadUIStatPoller");
    }

    function getAverageUIStats(resp) {
      var rv = {};
      (["index_memory_quota","index_memory_used","index_remaining_ram","index_ram_percent",
        "index/fragmentation","index/data_size","index/disk_size","index/num_rows_returned"])
        .forEach(function (statName) {
        var stats = resp.data.samples[statName];
        if (stats) {
          rv[statName] = stats.reduce(function (sum, stat) {
            return sum + stat;
          }, 0) / stats.length;
        }
      });
      vm.stats = rv;
    }
  }
})();
