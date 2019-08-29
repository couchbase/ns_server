(function () {
  "use strict";

  angular
    .module('mnDetailStats', ["mnStatisticsNewService", "mnStatisticsChart", "mnHelper", "mnStatisticsDescriptionService"])
    .directive('mnDetailStats', mnDetailStatsDirective);

  function mnDetailStatsDirective(mnStatisticsNewService, mnStatisticsDescriptionService, mnHelper) {
    var mnDetailStats = {
      restrict: "AE",
      scope: {
        mnTitle: "@",
        bucket: "@",
        itemId: "@",
        service: "@",
        prefix: "@",
        nodeName: "@?"
      },
      templateUrl: "app/components/directives/mn_detail_stats.html",
      controller: controller,
      controllerAs: "thisCtl"
    };

    return mnDetailStats;

    function controller($scope) {
      var vm = this;
      vm.zoom = "minute";
      vm.onSelectZoom = onSelectZoom;
      vm.items = {};

      activate();

      function onSelectZoom() {
        activate();
      }

      function getStats(stat) {
        var rv = {};
        rv["@" + $scope.service + "-.@items." + stat] = true;
        return rv;
      }

      function activate() {
        mnStatisticsNewService.doGetStats({
          zoom: vm.zoom,
          bucket: $scope.bucket,
          node: $scope.nodeName || "all",
        }).then(function (rv) {
          vm.items[$scope.service] = $scope.prefix + "/" + $scope.itemId + "/";
          vm.charts = Object
            .keys(mnStatisticsDescriptionService.stats["@" + $scope.service + "-"]["@items"])
            .filter(function (stat) {
              var service = "@" + $scope.service + "-";
              return !!mnStatisticsDescriptionService.stats[service]["@items"][stat] &&
                !!rv.data.stats[service + $scope.bucket][vm.items[$scope.service] + stat];
            })
            .map(function (stat) {
              return {
                node: $scope.nodeName,
                preset: true,
                id: mnHelper.generateID(),
                isSpecific: false,
                size: "small",
                stats: getStats(stat)
              };
            });
        });
      }
    }
  }
})();
