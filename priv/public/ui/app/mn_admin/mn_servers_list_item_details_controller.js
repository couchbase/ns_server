import mnStatsDesc from "./mn_statistics_description.js";

export default mnServersListItemDetailsController;

function mnServersListItemDetailsController($scope, mnServersListItemDetailsService, mnPromiseHelper, mnStatisticsNewService, mnPermissions, mnPoolDefault) {
  var vm = this;

  $scope.$watch('node', function (node) {
    mnPromiseHelper(vm, mnServersListItemDetailsService.getNodeDetails(node))
      .applyToScope("server");
  });

  $scope.$watchGroup(['node', 'adminCtl.tasks'], function (values) {
    vm.tasks = mnServersListItemDetailsService.getNodeTasks(values[0], values[1]);
  });

  let statsNames = [
    '@index.index_memory_used',
    '@fts.fts_num_bytes_used_ram',
    '@cbas.cbas_heap_used',
    '@cbas.cbas_disk_used'
  ];

  statsNames =
    mnPoolDefault.export.compat.atLeast70 ? statsNames.map(mnStatsDesc.mapping65) : statsNames;
  vm.getLatestStat =
    mnPoolDefault.export.compat.atLeast70 ? getLatestStat70 : getLatestStat;

  mnStatisticsNewService.subscribeUIStatsPoller({
    node: $scope.node.hostname || "all",
    zoom: 3000,
    step: 1,
    bucket: mnPermissions.export.bucketNames['.stats!read'] &&
      mnPermissions.export.bucketNames['.stats!read'][0],
    stats: statsNames
  }, $scope);

  $scope.$watch("mnUIStats", updateBarChartData);

  $scope.$watch("serversListItemDetailsCtl.server", updateBarChartData);

  function getLatestStat(statName, stats) {
    return stats.stats[statName] && stats.stats[statName][$scope.node.hostname];
  }

  function getLatestStat70(statName, stats) {
    return stats.stats[statName] &&
      stats.stats[statName][$scope.node.hostname].values.map(([_, v])=> v);
  }

  function updateBarChartData() {
    if (!vm.server) {
      return;
    }
    var details = vm.server.details;
    var ram = details.storageTotals.ram;
    var hdd = details.storageTotals.hdd;
    var stats = $scope.mnUIStats;

    vm.memoryUsages = [];
    vm.diskUsages = [];

    if (details.services.includes("kv")) {
      vm.memoryUsages.push(
        mnServersListItemDetailsService.getBaseConfig(
          'quota allocated to buckets',
          ram.quotaUsedPerNode,
          ram.quotaTotalPerNode, true),
        mnServersListItemDetailsService.getBaseConfig(
          'data service used',
          ram.usedByData,
          ram.quotaTotalPerNode, true)
      );

      vm.diskUsages.push(mnServersListItemDetailsService.getBaseConfig(
        'data service',
        hdd.usedByData,
        hdd.free));
    }

    if (!stats) {
      return;
    }

    vm.isEnterprise = $scope.poolDefault.isEnterprise;

    vm.memoryUsages.push(
      mnServersListItemDetailsService.getBaseConfig(
        'index service used',
        vm.getLatestStat(statsNames[0], stats),
        details.indexMemoryQuota*1024*1024, true),
      mnServersListItemDetailsService.getBaseConfig(
        'search service used',
        vm.getLatestStat(statsNames[1], stats),
        details.ftsMemoryQuota*1024*1024, true),
      mnServersListItemDetailsService.getBaseConfig(
        'analytics service used',
        vm.getLatestStat(statsNames[2], stats),
        details.cbasMemoryQuota*1024*1024, true)
    );

    ([
      //{name: 'couch_views_actual_disk_size', label: "views"},
      //{name: 'index/disk_size', label: "indexes"},
      //{name: 'fts/num_bytes_used_disk', label: "analytics"},
      {name: statsNames[3], label: "analytics service"}
    ]).forEach(function (stat, i) {
      vm.diskUsages.push(mnServersListItemDetailsService.getBaseConfig(
        stat.label,
        vm.getLatestStat(stat.name, stats),
        hdd.free))
    });

  }

}
