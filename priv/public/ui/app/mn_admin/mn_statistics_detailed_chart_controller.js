export default mnStatisticsDetailedChartController;

function mnStatisticsDetailedChartController($scope, $timeout, $state, chart, items, mnStatisticsNewService) {
  var vm = this;
  vm.chart = Object.assign({}, chart, {size: "extra"});

  vm.items = items;
  vm.onSelectZoom = onSelectZoom;
  vm.bucket = $state.params.scenarioBucket;
  vm.zoom = $state.params.scenarioZoom !== "minute" ? $state.params.scenarioZoom : "hour";
  vm.node = $state.params.statsHostname;
  vm.options = {showFocus: true, showTicks: true, showLegends: true};

  mnStatisticsNewService.mnAdminStatsPoller.heartbeat.setInterval(
    mnStatisticsNewService.defaultZoomInterval(vm.zoom));

  function onSelectZoom(selectedOption) {
    vm.options.showFocus = selectedOption !== "minute";
    mnStatisticsNewService.mnAdminStatsPoller.heartbeat.setInterval(
      mnStatisticsNewService.defaultZoomInterval(selectedOption));
    vm.reloadChartDirective = true;
    $timeout(function () {
      vm.reloadChartDirective = false;
    });
  }

  $scope.$on("$destroy", function () {
    mnStatisticsNewService.mnAdminStatsPoller.heartbeat.setInterval(
      mnStatisticsNewService.defaultZoomInterval($state.params.scenarioZoom));
    mnStatisticsNewService.mnAdminStatsPoller.heartbeat.reload();
  });

}
