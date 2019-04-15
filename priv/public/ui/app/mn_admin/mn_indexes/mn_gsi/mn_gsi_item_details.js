(function () {
  "use strict";

  angular
    .module('mnGsi')
    .directive('mnGsiItemDetails', mnGsiItemDetails);

  function mnGsiItemDetails() {
    var mnGsiItemDetails = {
      restrict: 'E',
      scope: {
        row: "=",
        rbac: "="
      },
      controller: mnGsiItemDetailsController,
      controllerAs: "mnGsiItemDetailsCtl",
      templateUrl: 'app/mn_admin/mn_indexes/mn_gsi/mn_gsi_item_details.html'
    };

    return mnGsiItemDetails;

    function mnGsiItemDetailsController($state, $scope, mnStatisticsNewService, mnPoolDefault, mnHelper, mnStatisticsDescriptionService) {
      var vm = this;
      vm.hasQueryService = hasQueryService;
      vm.onSelectZoom = onSelectZoom;
      vm.onSelectPartition = onSelectPartition;

      vm.zoom = "minute";

      function getRow() {
        return $scope.row.partitions ? $scope.row.partitions[vm.selectedPartition] : $scope.row;
      }

      if ($scope.row.partitions) {
        vm.selectedPartition = $scope.row.instId.toString();
      }

      activate();

      function onSelectZoom() {
        activate();
      }

      function onSelectPartition() {
        activate();
      }

      function getStats(stat) {
        var rv = {};
        rv[stat] = "@index-.@items";
        return rv;
      }

      function activate() {
        var row = getRow();
        vm.hosts = row.hosts.join(', ');
        mnStatisticsNewService.doGetStats({
          zoom: vm.zoom,
          bucket: row.bucket
        }).then(function (rv) {
          vm.charts = Object
            .keys(rv.data.stats["@index-" + row.bucket])
            .filter(function (key) {
              var stat = key.split("/")[2];
              var indexName = key.split("/")[1];
              return indexName == row.index &&
                mnStatisticsNewService.readByPath("@index-.@items", stat);
            })
            .map(function (stat) {
              return {
                preset: true,
                id: mnHelper.generateID(),
                isSpecific: false,
                size: "small",
                zoom: vm.zoom,
                stats: getStats(stat)
              };
            });
        });
      }


      // we can show Edit / Delete buttons if there is a query service
      function hasQueryService() {
        return (mnPoolDefault.export.thisNode.services.indexOf('n1ql') != -1);
      }

    }
  }
})();
