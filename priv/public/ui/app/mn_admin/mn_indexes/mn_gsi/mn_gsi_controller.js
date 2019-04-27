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
  ]).controller('mnGsiController', mnGsiController);

  function mnGsiController($scope, mnGsiService, mnPoller, mnPermissions) {
    var vm = this;
    vm.focusindexFilter = false;
    vm.currentBucket = mnPermissions.export.bucketNames['.stats!read'][0];
    vm.onSelectBucket = getStats;

    function activate() {
      new mnPoller($scope, function () {
       return mnGsiService.getIndexesState();
      })
      .setInterval(10000)
      .subscribe("state", vm)
      .reloadOnScopeEvent("indexStatusURIChanged")
      .cycle();

      new mnPoller($scope, getStats)
      .setInterval(5000)
      .subscribe("stats", vm)
      .cycle();
    }

    // for the index display, the following array has the list of stats
    var stat_names = ["cbas_disk_used","index_memory_quota","index_memory_used","index_ram_percent","index_remaining_ram",
      "ep_dcp_views+indexes_count","ep_dcp_views+indexes_items_remaining","ep_dcp_views+indexes_producer_count",
      "ep_dcp_views+indexes_total_backlog_size","ep_dcp_views+indexes_total_bytes","ep_dcp_views+indexes_backoff",
      "index/fragmentation","index/memory_used","index/disk_size","index/data_size"];

    function getStats() {
      return mnGsiService.getIndexStats(stat_names,vm.currentBucket).then(function success(resp) {
        var result = {};
        if (resp) resp.forEach(function (aStat) {
          if (aStat.data && aStat.data.statName && aStat.data.stats.aggregate.samples.length > 0) {
            var sum = 0;
            for (var i=0; i<aStat.data.stats.aggregate.samples.length; i++)
              sum += aStat.data.stats.aggregate.samples[i];
            result[aStat.data.statName] = sum/aStat.data.stats.aggregate.samples.length;
          }
        });
        return result;
      });
    }

    // done with config
    activate();
  }
})();
