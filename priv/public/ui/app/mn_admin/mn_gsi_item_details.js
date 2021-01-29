import _ from "/ui/web_modules/lodash.js";
import mnStatsDesc from "./mn_statistics_description.js";

export {mnGsiItemController, mnGsiItemStatsController, mnGsiItemDetails};

function mnGsiItemStatsController($scope) {
  var vm = this;
  vm.zoom = "minute";
  vm.onSelectZoom = onSelectZoom;

  activate();

  function onSelectZoom() {
    activate();
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

function mnGsiItemController($scope, mnStatisticsNewService, mnPoolDefault, mnPermissions) {
  var vm = this;
  var row = $scope.row;

  let interestingPermissions = row.collection ?
      mnPermissions.getPerCollectionPermissions(row.bucket, row.scope, row.collection) :
      mnPermissions.getPerScopePermissions(row.bucket, row.scope);
  interestingPermissions.forEach(mnPermissions.set);
  mnPermissions.throttledCheck();

  $scope.$on("$destroy", onDestroy);


  function onDestroy() {
    interestingPermissions.forEach(mnPermissions.remove);
  }

}

function mnGsiItemDetails() {
  var mnGsiItemDetails = {
    restrict: 'E',
    scope: {
      row: "=",
      rbac: "=",
      pools: "=",
      nodeName: "@?"
    },
    controller: mnGsiItemDetailsController,
    controllerAs: "mnGsiItemDetailsCtl",
    templateUrl: 'app/mn_admin/mn_gsi_item_details.html'
  };

  return mnGsiItemDetails;

  function mnGsiItemDetailsController($rootScope, $scope, mnGsiService, $uibModal, $filter, mnPromiseHelper, mnAlertsService) {
    var vm = this;
    vm.dropIndex = dropIndex;
    vm.getFormattedScanTime = getFormattedScanTime;
    var row = $scope.row;

    vm.keyspace = row.bucket + ":" + row.scope + (row.collection ? (":" + row.collection) : "");

    function getFormattedScanTime(row) {
      if (row && row.lastScanTime != 'NA')
        return $filter('date')(Date.parse(row.lastScanTime), 'hh:mm:ss a, d MMM, y');
      else
        return 'NA';
    }

    function dropIndex(row) {
      var scope = $rootScope.$new();
      scope.partitioned = row.partitioned;
      $uibModal.open({
        windowClass: "z-index-10001",
        backdrop: 'static',
        templateUrl: 'app/mn_admin/mn_gsi_drop_confirm_dialog.html',
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
          .showGlobalSuccess("Index dropped successfully!")
          .catchGlobalErrors("Error dropping index.");
      });
    }

  }
}
