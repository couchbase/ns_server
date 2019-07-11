(function () {
  "use strict";

  angular
    .module('mnGsi')
    .controller('mnGsiItemController', mnGsiItemController)
    .controller('mnGsiItemStatsController', mnGsiItemStatsController)
    .directive('mnGsiItemDetails', mnGsiItemDetails);

  function mnGsiItemStatsController(mnStatisticsNewService, mnHelper, $scope) {
    var vm = this;
    vm.getNvd3Options = getNvd3Options;
    vm.zoom = "minute";
    vm.onSelectZoom = onSelectZoom;
    vm.getNvd3Options = getNvd3Options;

    activate();

    function onSelectZoom() {
      activate();
    }

    function getNvd3Options(config) {
      return {
        showLegend: false
      };
    }

    function getStats(stat) {
      var rv = {};
      rv[stat] = "@index-.@items";
      return rv;
    }

    function activate() {
      var row = $scope.row;
      vm.hosts = row.hosts.join(', ');
    }
  }

  function mnGsiItemController($scope, mnStatisticsNewService, mnPermissions) {
    var vm = this;

    vm.hasValue = hasValue;
    vm.hasNoValue = hasNoValue;

    if (!mnPermissions.export.cluster.bucket[$scope.row.bucket].stats.read) {
      return;
    }

    function hasNoValue(key) {
      return !!$scope.gsiItemCtl.stats &&
        ($scope.gsiItemCtl.stats[key] == undefined);
    }

    function hasValue(key) {
      return !!$scope.gsiItemCtl.stats &&
        ($scope.gsiItemCtl.stats[key] != undefined);
    }

    mnStatisticsNewService.subscribeUIStatsPoller({
      bucket: $scope.row.bucket,
      node: "all",
      zoom: 'minute'
    }, $scope);

    $scope.$watch("mnUIStats", function (resp) {
      if (!resp) {
        return
      }
      var rv = {};
      (["data_size","items_count","index_resident_percent",
        "num_docs_pending+queued","num_requests"]).forEach(function (statName) {
          var fullName = 'index/' + $scope.row.index + '/' + statName;
          var stats = resp.data.samples[fullName];
          if (stats) {
            rv[statName] =  stats.reduce(function (sum, stat) {
              return sum + stat;
            }, 0) / stats.length;
          }
        });
      vm.stats = rv;
    });

  }

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

    function mnGsiItemDetailsController($rootScope, mnGsiService, $uibModal, mnPromiseHelper, mnAlertsService) {
      var vm = this;
      vm.dropIndex = dropIndex;

      function dropIndex(row) {
        var scope = $rootScope.$new();
        scope.partitioned = row.partitioned;
        $uibModal.open({
          windowClass: "z-index-10001",
          backdrop: 'static',
          templateUrl: 'app/mn_admin/mn_indexes/mn_gsi/mn_gsi_drop_confirm_dialog.html',
          scope: scope
        }).result.then(function () {
          row.awaitingRemoval = true;
          mnPromiseHelper(vm, mnGsiService.postDropIndex(row))
            .showGlobalSpinner()
            .catchErrors(function (resp) {
              if (!resp) {
                return;
              } else if (_.isString(resp)) {
                mnAlertsService.formatAndSetAlerts(resp.data, "error", 4000);
              } else if (resp.errors && resp.errors.length) {
                mnAlertsService.formatAndSetAlerts(_.map(resp.errors, "msg"), "error", 4000);
              }
              row.awaitingRemoval = false;
            })
            .showGlobalSuccess("Index dropped successfully!");
        });
      }

    }
  }
})();
