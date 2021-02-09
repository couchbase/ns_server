import mnStatsDesc from "./mn_statistics_description.js";

export default mnGsiFooterController;

function mnGsiFooterController($scope, $rootScope, $state, mnStatisticsNewService, mnPoolDefault, mnPermissions) {
  var vm = this;

  vm.onSelectBucket = onSelectBucket;

  vm.getLatestStat = mnPoolDefault.export.compat.atLeast70 ? getLatestStat70 : getLatestStat;

  vm.currentBucket = $state.params.footerBucket ||
    (mnPermissions.export.bucketNames['.stats!read'] &&
     mnPermissions.export.bucketNames['.stats!read'][0]);

  vm.mnGSIFooterStatsPoller = mnStatisticsNewService.createStatsPoller($scope);

  vm.stats = $scope.stats || (mnPoolDefault.export.compat.atLeast70 ? [
    '@index.index_memory_quota','@index.index_memory_used_total',
    '@index-.index_num_rows_returned','@index-.index_fragmentation',
    '@index-.index_data_size','@index-.index_disk_size'
  ] : [
    '@index.index_memory_quota','@index.index_memory_used',
    '@index.index_remaining_ram','@index.index_ram_percent',
    '@index-.index/num_rows_returned','@index-.index/fragmentation',
    '@index-.index/data_size','@index-.index/disk_size']);

  var config = {
    bucket: vm.currentBucket,
    node: "all",
    zoom: 3000,
    step: 1,
    stats: vm.stats
  };

  activate();

  function activate() {
    vm.mnGSIFooterStatsPoller.subscribeUIStatsPoller(config, $scope);
  }

  function doGetLatestStat70(statName) {
    var stats = $scope.mnUIStats && $scope.mnUIStats.stats;
    return stats && stats[statName]  && stats[statName].aggregate &&
      Number(stats[statName].aggregate.values.slice().reverse().find(stat => stat != null)[1]);
  }

  function getLatestStat70(statName) {
    switch (statName) {
    case "@index.index_remaining_ram":
      let quota = doGetLatestStat70("@index.index_memory_quota");
      let used = doGetLatestStat70("@index.index_memory_used_total");
      return used > quota ? 0 : quota - used;
    case "@index.index_ram_percent":
      return doGetLatestStat70("@index.index_memory_used_total") /
        doGetLatestStat70("@index.index_memory_quota") * 100;
    default:
      return doGetLatestStat70(mnStatsDesc.mapping65(statName));
    }
  }

  function getLatestStat(statName) {
    statName = statName.split(".").pop();
    return $scope.mnUIStats &&
      $scope.mnUIStats.stats[statName] &&
      $scope.mnUIStats.stats[statName].aggregate.slice().reverse().find(stat => stat != null);
  }

  function onSelectBucket() {
    //reload ng-controller in the template
    $rootScope.$apply(() => {
      $rootScope.destroyGsiFooter = true;
    });
    $state.go(".", {footerBucket: vm.currentBucket}).then(function () {
      $rootScope.destroyGsiFooter = false;
    });
  }

}
