(function () {
  "use strict";

  angular
    .module("mnStatisticsNew")
    .controller("mnStatisticsDetailedChartController", mnStatisticsDetailedChartController)

  function mnStatisticsDetailedChartController(chart, $timeout, $state) {
    var vm = this;
    vm.chart = Object.assign({}, chart, {size: "extra"});

    vm.onSelectZoom = onSelectZoom;
    vm.bucket = $state.params.scenarioBucket;
    vm.zoom = "hour";

    function onSelectZoom() {
      vm.reloadChartDirective = true;
      $timeout(function () {
        vm.reloadChartDirective = false;
      });
    }

  }
})();
