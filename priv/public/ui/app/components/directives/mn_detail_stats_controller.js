(function () {
  "use strict";

  angular
    .module('mnDetailStats', ["mnStatisticsNewService", "mnStatisticsChart", "mnHelper", "mnStatisticsDescriptionService"])
    .directive('mnDetailStats', mnDetailStatsDirective);

  function mnDetailStatsDirective(mnStatisticsNewService, mnStatisticsDescriptionService, mnHelper) {
    var mnDetailStats = {
      restrict: "AE",
      scope: {
        title: "@",
        bucket: "@",
        itemId: "@",
        service: "@",
        prefix: "@"
      },
      templateUrl: "app/components/directives/mn_detail_stats.html",
      controller: controller,
      controllerAs: "thisCtl"
    };

    return mnDetailStats;

    function controller($scope) {
      var vm = this;
      vm.getNvd3Options = getNvd3Options;
      vm.zoom = "minute";
      vm.onSelectZoom = onSelectZoom;

      activate();

      function onSelectZoom() {
        activate();
      }

      function getNvd3Options() {
        return {
          showLegend: false
        };
      }

      function getStats(stat) {
        var rv = {};
        rv[stat] = "@" + $scope.service + "-.@items";
        return rv;
      }

      function activate() {
        mnStatisticsNewService.doGetStats({
          zoom: vm.zoom,
          bucket: $scope.bucket
        }).then(function (rv) {

          vm.charts = Object
            .keys(mnStatisticsDescriptionService.stats["@" + $scope.service + "-"]["@items"])
            .filter(function (stat) {
              return mnStatisticsDescriptionService.stats["@" + $scope.service + "-"]["@items"][stat] && !!rv.data.stats["@" + $scope.service + "-" + $scope.bucket][$scope.prefix + "/" + $scope.itemId + "/" + stat];
            })
            .map(function (stat) {
              return {
                preset: true,
                id: mnHelper.generateID(),
                isSpecific: false,
                size: "small",
                zoom: vm.zoom,
                stats: getStats($scope.prefix + "/" + $scope.itemId + "/" + stat)
              };
            });
        });
      }
    }
  }
})();
