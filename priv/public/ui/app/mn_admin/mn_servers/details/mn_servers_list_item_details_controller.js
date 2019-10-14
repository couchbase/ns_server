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
        zoom: 'minute',
        interval: 5000,
        bucket: mnPermissions.export.bucketNames['.stats!read'] &&
          mnPermissions.export.bucketNames['.stats!read'][0]
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
        var stats = $scope.mnUIStats && $scope.mnUIStats.data && $scope.mnUIStats.data.samples;

        vm.memoryUsages = [];
        vm.diskUsages = [];

        if (details.services.includes("kv")) {
          vm.memoryUsages.push(
            mnServersListItemDetailsService.getBaseConfig(
              'quota allocated to buckets',
              ram.quotaUsedPerNode,
              ram.quotaTotalPerNode),
            mnServersListItemDetailsService.getBaseConfig(
              'Data Service',
              ram.usedByData,
              ram.quotaTotalPerNode)
          );

          vm.diskUsages.push(mnServersListItemDetailsService.getBaseConfig(
              'Data Service',
              hdd.usedByData,
              hdd.free));
        }

        if (!stats) {
          return;
        }

        vm.memoryUsages.push(
          mnServersListItemDetailsService.getBaseConfig(
            'Index Service',
            stats['index_memory_used'],
            details.indexMemoryQuota*1024*1024),
          mnServersListItemDetailsService.getBaseConfig(
            'Search Service',
            stats['fts_num_bytes_used_ram'],
            details.ftsMemoryQuota*1024*1024),
          mnServersListItemDetailsService.getBaseConfig(
            'Analytics Service',
            stats['cbas_heap_used'],
            details.cbasMemoryQuota*1024*1024)
        );

        ([
          //{name: 'couch_views_actual_disk_size', label: "views"},
          //{name: 'index/disk_size', label: "indexes"},
          //{name: 'fts/num_bytes_used_disk', label: "analytics"},
          {name: 'cbas_disk_used', label: "Analytics Service"}
        ]).forEach(function (stat) {
          vm.diskUsages.push(mnServersListItemDetailsService.getBaseConfig(
            stat.label,
            stats[stat.name],
            hdd.free,
            hdd.usedByData))
        });

      }

    }
})();
