(function () {
  "use strict";

  angular
    .module('mnServers')
    .controller('mnServersListItemDetailsController', mnServersListItemDetailsController)

    function mnServersListItemDetailsController($scope, mnServersListItemDetailsService, mnPromiseHelper, mnPoller, mnStatisticsNewService, mnPermissions) {
      var vm = this;

      $scope.$watch('node', function (node) {
        mnPromiseHelper(vm, mnServersListItemDetailsService.getNodeDetails(node))
          .applyToScope("server");
      });

      $scope.$watchGroup(['node', 'adminCtl.tasks'], function (values) {
        vm.tasks = mnServersListItemDetailsService.getNodeTasks(values[0], values[1]);
      });

      mnStatisticsNewService.subscribeUIStatsPoller({
        node: $scope.node.hostname || "all",
        zoom: 1000,
        step: 1,
        bucket: mnPermissions.export.bucketNames['.stats!read'] &&
          mnPermissions.export.bucketNames['.stats!read'][0],
        stats: ['index_memory_used','fts_num_bytes_used_ram','cbas_heap_used','cbas_disk_used']
      }, $scope);

      $scope.$watch("mnUIStats", updateBarChartData);

      $scope.$watch("serversListItemDetailsCtl.server", updateBarChartData);

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
              ram.quotaTotalPerNode),
            mnServersListItemDetailsService.getBaseConfig(
              'data service used',
              ram.usedByData,
              ram.quotaTotalPerNode)
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
            stats[0].stats[$scope.node.hostname].samples,
            details.indexMemoryQuota*1024*1024),
          mnServersListItemDetailsService.getBaseConfig(
            'search service used',
            stats[1].stats[$scope.node.hostname].samples,
            details.ftsMemoryQuota*1024*1024),
          mnServersListItemDetailsService.getBaseConfig(
            'analytics service used',
            stats[2].stats[$scope.node.hostname].samples,
            details.cbasMemoryQuota*1024*1024)
        );

        ([
          //{name: 'couch_views_actual_disk_size', label: "views"},
          //{name: 'index/disk_size', label: "indexes"},
          //{name: 'fts/num_bytes_used_disk', label: "analytics"},
          {name: 'cbas_disk_used', label: "analytics service"}
        ]).forEach(function (stat, i) {
          vm.diskUsages.push(mnServersListItemDetailsService.getBaseConfig(
            stat.label,
            stats[i + 3].stats[$scope.node.hostname].samples,
            hdd.free,
            hdd.usedByData))
        });

      }

    }
})();
