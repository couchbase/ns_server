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
    'mnStatisticsNewService',
    'mnDetailStats'
  ]).controller('mnGsiController', mnGsiController)
    .controller('mnFooterStatsController', mnFooterStatsController);

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

  function mnFooterStatsController($scope, mnStatisticsNewService, mnPoller, mnPermissions) {
    var vm = this;
    vm.currentBucket = mnPermissions.export.bucketNames['.stats!read'] &&
      mnPermissions.export.bucketNames['.stats!read'][0];
    vm.onSelectBucket = onSelectBucket;
    vm.getLatestStat = getLatestStat;
    vm.getLatestStatExponent = getLatestStatExponent;

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
        .subscribe(function (rv) {
          vm.stats = rv.data.samples;
        }, vm)
        .reloadOnScopeEvent("reloadUIStatPoller")
        .cycle();
    }

    function getLatestStat(statName) {
      if (vm.stats && _.isArray(vm.stats[statName])) {
        return(vm.stats[statName].slice(-1)[0]);
      }
    }

    function getLatestStatExponent(statName, digits) {
      var value = getLatestStat(statName);
      if (value) {
        return(d3.format('.'+digits+'e')(value));
      }
      else {
        return value;
      }
    }

    function onSelectBucket() {
      $scope.$broadcast("reloadUIStatPoller");
    }

  }
})();
