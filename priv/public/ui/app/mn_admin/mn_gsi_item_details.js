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

function mnGsiItemController($scope, mnStatisticsNewService, mnPoolDefault) {
  var vm = this;

  var stats = mnPoolDefault.export.compat.atLeast70 ? [
    "@index-.@items.index_num_requests", "@index-.@items.index_resident_percent",
    "@index-.@items.index_items_count", "@index-.@items.index_data_size",
    "@index-.@items.index_num_docs_pending", "@index-.@items.index_num_docs_queued"
  ] : [
    "@index-.@items.num_requests", "@index-.@items.index_resident_percent",
    "@index-.@items.items_count", "@index-.@items.data_size",
    "@index-.@items.num_docs_pending+queued"
  ];
  var getStatSamples = mnPoolDefault.export.compat.atLeast70 ?
      getStatSamples70 : getStatSamplesPre70;

  mnStatisticsNewService.subscribeUIStatsPoller({
    bucket: $scope.row.bucket,
    node: $scope.nodeName || "all",
    zoom: 3000,
    step: 1,
    stats: stats,
    items: {
      index: mnPoolDefault.export.compat.atLeast70 ?
        $scope.row.index : ("index/" + $scope.row.index + "/")
    }
  }, $scope);

  $scope.$watch("mnUIStats", updateValues);
  $scope.$watch("row", updateValues);

  function getIndexStatName(statName) {
    return 'index/' + $scope.row.index + '/' + statName;
  }

  function doGetStatSamples70(statName) {
    var stats = $scope.mnUIStats && $scope.mnUIStats.stats;
    return stats && stats[statName] && stats[statName] &&
      stats[statName][$scope.nodeName || "aggregate"] &&
      Number(stats[statName][$scope.nodeName || "aggregate"]
             .values.slice().reverse().find(stat => stat != null)[1]);
  }

  function getStatSamples70(statName) {
    switch (statName) {
    case "num_docs_pending+queued":
      return doGetStatSamples70("@index-.@items.index_num_docs_pending") +
        doGetStatSamples70("@index-.@items.index_num_docs_queued");
    default:
      return doGetStatSamples70(mnStatsDesc.mapping65("@index-.@items." + statName));
    }
  }

  function getStatSamplesPre70(statName) {
    return $scope.mnUIStats &&
      $scope.mnUIStats.stats[getIndexStatName(statName)] &&
      $scope.mnUIStats.stats[getIndexStatName(statName)][$scope.nodeName || "aggregate"]
      .slice().reverse().find(stat => stat != null);
  }

  function updateValues() {
    (['num_requests', 'index_resident_percent', 'items_count', 'data_size', 'num_docs_pending+queued'])
      .forEach(function (statName) {
        var value = getStatSamples(statName);
        vm['has_' + statName] = parseFloat(value) === value;
        vm['has_no_' + statName] = parseFloat(value) !== value;
        if (vm['has_' + statName]) {
          //set value to the row, so we can use it for sorting later
          $scope.row[statName] = value;
        }
      });
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

  function mnGsiItemDetailsController($rootScope, mnGsiService, $uibModal, $filter, mnPromiseHelper, mnAlertsService) {
    var vm = this;
    vm.dropIndex = dropIndex;
    vm.getFormattedScanTime = getFormattedScanTime;

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
