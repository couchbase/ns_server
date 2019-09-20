(function () {
  "use strict";

  angular
    .module('mnServers')
    .controller('mnServersListItemDetailsController', mnServersListItemDetailsController)

    function mnServersListItemDetailsController($scope, mnServersListItemDetailsService, mnPromiseHelper, mnPoller, mnStatisticsNewService, mnPermissions) {
      var vm = this;

      $scope.$watch('node', function (node) {
        if (node != vm.node) {
          vm.node = node;
          if (vm.statsPoller) {
            vm.statsPoller.stop();
          }
          vm.statsPoller = new mnPoller($scope, function (previousResult) {
            return mnStatisticsNewService.doGetStats({
              zoom: "minute",
              bucket: vm.currentBucket,
              node: vm.node.hostname
            }, previousResult);
          })
            .setInterval(5000)
            .subscribe(function (rv) {
              vm.stats = rv.data.samples;
              updateBarChartData();
            }, vm)
            .reloadOnScopeEvent("reloadUIStatPoller")
            .cycle();
        }

        vm.node = node;

        mnPromiseHelper(vm, mnServersListItemDetailsService.getNodeDetails(node))
          .applyToScope("server");
      });
      $scope.$watchGroup(['node', 'adminCtl.tasks'], function (values) {
        vm.tasks = mnServersListItemDetailsService.getNodeTasks(values[0], values[1]);
      });

      vm.currentBucket = mnPermissions.export.bucketNames['.stats!read'] &&
      mnPermissions.export.bucketNames['.stats!read'][0];

      function updateBarChartData() {
        if (vm.server && vm.server.details.storageTotals && vm.server.details.storageTotals.ram) {
          vm.allocatedMemory = { items: [
            {name: 'quota allocated to buckets', value: vm.server.details.storageTotals.ram.quotaUsedPerNode},
            {name: 'remaining ', value: vm.server.details.storageTotals.ram.quotaTotalPerNode - vm.server.details.storageTotals.ram.quotaUsedPerNode}]};
          vm.usedMemory = { items: [
            {name: 'Data Service', value: vm.server.details.storageTotals.ram.usedByData},
            {name: 'remaining quota ', value: vm.server.details.storageTotals.ram.quotaTotalPerNode - vm.server.details.storageTotals.ram.quotaUsedPerNode}]};
        }

        if (vm.stats && vm.stats['index_memory_used'] && vm.stats['index_memory_quota']) {
          vm.indexMemory = { items: [
            {name: 'Index Service', value: vm.stats['index_memory_used'].slice(-1)[0]},
            {name: 'remaining quota ', value: vm.stats['index_memory_quota'].slice(-1) - vm.stats['index_memory_used'].slice(-1)[0]}]};
        }

        if (vm.server && vm.server.details.ftsMemoryQuota && vm.stats['fts_num_bytes_used_ram']) {
          vm.ftsMemory = { items: [
            {name: 'Search Service', value: vm.stats['fts_num_bytes_used_ram'].slice(-1)[0]},
            {name: 'remaining quota ', value: vm.server.details.ftsMemoryQuota*1024*1024 - vm.stats['fts_num_bytes_used_ram'].slice(-1)[0]}]};
        }

        if (vm.server && vm.server.details.cbasMemoryQuota && vm.stats['cbas_heap_used']) {
          vm.cbasMemory = { items: [
            {name: 'Analytics Service', value: vm.stats['cbas_heap_used'].slice(-1)[0]},
            {name: 'remaining quota ', value: vm.server.details.cbasMemoryQuota*1024*1024 - vm.stats['cbas_heap_used'].slice(-1)[0]}]};
        }

        if (vm.server && vm.server.details.storageTotals && vm.server.details.storageTotals.hdd) {
          var free = vm.server.details.storageTotals.hdd.free - vm.server.details.storageTotals.hdd.usedByData;
          vm.diskUsages = [];
          vm.diskUsages.push({items: [
            {name: 'Data Service', value: vm.server.details.storageTotals.hdd.usedByData},
            {name: 'free', value: free}
          ]});

          var stats = [
            //{name: 'couch_views_actual_disk_size', label: "views"},
            //{name: 'index/disk_size', label: "indexes"},
            //{name: 'fts/num_bytes_used_disk', label: "analytics"},
            {name: 'cbas_disk_used', label: "Analytics Service"}
            ];

          stats.forEach(function(stat) {
            var statValue = _.isArray(vm.stats[stat.name]) ? vm.stats[stat.name].slice(-1)[0] : null;
            if (statValue) {
              vm.diskUsages.push({items: [{name: stat.label, value: statValue}, {name: 'free', value: free}]});
            }
          });
        }

      }

    }
})();
