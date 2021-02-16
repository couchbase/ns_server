import angular from "/ui/web_modules/angular.js";
import {equals} from '/ui/web_modules/ramda.js';

import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";
import uiRouter from "/ui/web_modules/@uirouter/angularjs.js";

import mnPoll from "/ui/app/components/mn_poll.js";
import mnFilters from "/ui/app/components/mn_filters.js";
import mnSpinner from "/ui/app/components/directives/mn_spinner.js";
import mnHelper from "/ui/app/components/mn_helper.js";
import mnStoreService from "/ui/app/components/mn_store_service.js";
import mnDropdown from "/ui/app/components/directives/mn_dropdown.js";

import mnStatisticsChart from "./mn_statistics_chart_directive.js";
import mnStatisticsNewService from "./mn_statistics_service.js";
import mnStatisticsDescriptionService from "./mn_statistics_description_service.js";
import mnUserRolesService from "./mn_user_roles_service.js";
import mnGsiService from "./mn_gsi_service.js";

import mnStatisticsDetailedChartController from "./mn_statistics_detailed_chart_controller.js";
import mnGroupDialogController from "./mn_statistics_group_controller.js";
import mnScenarioDialogController from "./mn_statistics_scenario_controller.js";
import {mnStatisticsNewChartBuilderController, mnFormatStatsSections} from "./mn_statistics_chart_builder_controller.js";

export default "mnStatisticsNew";

angular
  .module('mnStatisticsNew', [
    uiRouter,
    uiBootstrap,
    mnPoll,
    mnHelper,
    mnSpinner,
    mnFilters,
    mnDropdown,
    mnStatisticsChart,
    mnStatisticsNewService,
    mnStatisticsDescriptionService,
    mnUserRolesService,
    mnStoreService,
    mnGsiService
  ])
  .controller('mnStatisticsNewController', mnStatisticsNewController)
  .controller('mnStatisticsGroupsController', mnStatisticsGroupsController)
  .controller('mnStatisticsChartsController', mnStatisticsChartsController)
  .controller('mnScenarioDialogController', mnScenarioDialogController)
  .controller('mnStatisticsDetailedChartController', mnStatisticsDetailedChartController)
  .controller('mnGroupDialogController', mnGroupDialogController)
  .controller("mnStatisticsNewChartBuilderController", mnStatisticsNewChartBuilderController)
  .filter("mnFormatStatsSections", mnFormatStatsSections);

function mnStatisticsChartsController($scope, $uibModal, mnStatisticsNewService, mnStoreService, mnHelper, mnUserRolesService, $timeout) {
  var vm = this;

  vm.deleteChart = deleteChart;
  vm.editChart = editChart;
  vm.openDetailedChartDialog = openDetailedChartDialog;
  vm.getChart = getChart;
  vm.api = {};

  $scope.$watch("statisticsNewCtl.chartsById[chartID]", function (a,b) {
    if (b && !equals(a,b)) {
      onItemChange();
    }
  })

  function onItemChange() {
    vm.reloadChartDirective = true;
    $timeout(function () {
      vm.reloadChartDirective = false;
      $scope.mnStatsGroupsCtl.maybeShowItemsControls();
    });
  }

  function getChart() {
    return $scope.statisticsNewCtl.chartsById &&
      $scope.statisticsNewCtl.chartsById[$scope.chartID];
  }

  function deleteChart() {
    vm.showChartControls = false;
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_statistics_chart_builder_delete.html'
    }).result.then(function () {
      mnStatisticsNewService.deleteChart($scope.chartID);
      mnUserRolesService.saveDashboard();
      $scope.mnStatsGroupsCtl.maybeShowItemsControls();
    });
  }

  function editChart(group, scenario) {
    vm.showChartControls = false;
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_statistics_chart_builder.html',
      controller: 'mnStatisticsNewChartBuilderController as builderCtl',
      resolve: {
        chart: mnHelper.wrapInFunction(vm.getChart()),
        group: mnHelper.wrapInFunction(group),
        scenario: mnHelper.wrapInFunction(scenario)
      }
    }).result.then(function () {
      mnUserRolesService.saveDashboard();
      onItemChange();
    });
  }

  function openDetailedChartDialog() {
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_statistics_detailed_chart.html',
      controller: 'mnStatisticsDetailedChartController as detailedChartCtl',
      windowTopClass: "chart-overlay",
      resolve: {
        items: mnHelper.wrapInFunction($scope.mnStatsGroupsCtl.items),
        chart: mnHelper.wrapInFunction(vm.getChart())
      }
    });
  }
}

function mnStatisticsGroupsController($scope, $uibModal, $timeout,
                                      mnStatisticsNewService, mnStoreService, mnUserRolesService) {
  var vm = this;
  vm.isDetailsOpened = true;
  vm.hideGroupControls = hideGroupControls;
  vm.onGroupNameBlur = onGroupNameBlur;
  vm.onGroupFocus = onGroupFocus;
  vm.onGroupSubmit = onGroupSubmit;
  vm.onGroupDelete = onGroupDelete;
  vm.deleteGroup = deleteGroup;
  vm.maybeShowItemsControls = maybeShowItemsControls;
  vm.saveDashboard = mnUserRolesService.saveDashboard;

  vm.items = {};
  vm.enabledItems = {};

  vm.getGroup = getGroup;

  maybeShowItemsControls();

  $scope.$watch("mnStatsGroupsCtl.items.index", onItemChange);
  $scope.$watch("mnStatsGroupsCtl.items.xdcr", onItemChange);
  $scope.$watch("mnStatsGroupsCtl.items.fts", onItemChange);
  $scope.$watch("mnStatsGroupsCtl.items.kv", onItemChange);

  function getGroup() {
    return $scope.statisticsNewCtl.groupsById &&
      $scope.statisticsNewCtl.groupsById[$scope.groupID];
  }

  function onItemChange() {
    vm.reloadChartDirective = true;
    $timeout(function () {
      vm.reloadChartDirective = false;
    });
  }

  function maybeShowItemsControls() {
    var items = {};
    ((vm.getGroup() || {}).charts || []).forEach(function (chartID) {
      var stats = mnStoreService.store("charts").get(chartID) ?
          mnStoreService.store("charts").get(chartID).stats : {};
      var chartStats = Object.keys(stats);
      chartStats.forEach(function (statPath) {
        if (statPath.includes("@items")) {
          items[statPath.split(".")[0]] = true;
        }
      });
    });
    vm.enabledItems = items;
  }

  function deleteGroup(groupID) {
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_statistics_group_delete.html',
    }).result.then(function () {
      mnStatisticsNewService.deleteGroup(groupID);
      mnUserRolesService.saveDashboard();
    });
  }

  function onGroupDelete() {
    vm.onControlClick = true;
    deleteGroup($scope.groupID);
    hideGroupControls();
  }

  function onGroupSubmit() {
    vm.initName = vm.getGroup().name;
    mnUserRolesService.saveDashboard()
    hideGroupControls();
    vm.focusOnSubmit = true;
  }

  function onGroupFocus() {
    vm.showGroupControls = true;
    vm.initName = vm.getGroup().name;
  }

  function onGroupNameBlur() {
    if (!vm.onControlClick) {
      vm.showGroupControls = false;
      vm.getGroup().name = vm.initName;
      mnStoreService.store("groups").put(vm.getGroup());
    }
  }

  function hideGroupControls() {
    if (vm.onControlClick) {
      vm.onControlClick = false;
      onGroupNameBlur();
    }
  }
}

function mnStatisticsNewController($scope, mnStatisticsNewService, $state, $http, mnPoller, $uibModal, mnHelper, $window, mnUserRolesService, permissions, $timeout, mnStoreService, mnGsiService, mnTasksDetails, $anchorScroll, $location) {
  var vm = this;

  vm.mnStatisticsNewScope = $scope;

  vm.onSelectScenario = onSelectScenario;
  vm.onSelectZoom = onSelectZoom;

  vm.bucket = $state.params.scenarioBucket;
  vm.zoom = $state.params.scenarioZoom;
  vm.node = $state.params.statsHostname;
  //selected scenario holder
  vm.openGroupDialog = openGroupDialog;
  vm.selectedBucket = $state.params.scenarioBucket;
  vm.onBucketChange = onBucketChange;
  vm.onSelectNode = onSelectNode;
  vm.getSelectedScenario = getSelectedScenario;

  vm.openChartBuilderDialog = openChartBuilderDialog;
  vm.resetDashboardConfiguration = resetDashboardConfiguration;
  vm.showBlocks = {
    "Server Resources": true
  };

  activate();

  function resetDashboardConfiguration() {
    return $uibModal.open({
      templateUrl: 'app/mn_admin/mn_statistics_reset_dialog.html'
    }).result
      .then(() => mnUserRolesService.resetDashboard())
      .then(() => {
        vm.scenarioId =
          mnStoreService.store("scenarios").last().id;
        $state.go("^.statistics", {
          scenario: mnStoreService.store("scenarios").last().id
        });
        $scope.$broadcast("scenariosChanged");
      });
  }

  function openGroupDialog() {
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_statistics_group.html',
      controller: 'mnGroupDialogController as groupDialogCtl',
      resolve: {
        scenarioId: mnHelper.wrapInFunction(vm.scenarioId)
      }
    }).result.then(function (group) {
      $location.hash('group-' + group.id);
      $anchorScroll();
    });
  }


  function openChartBuilderDialog(group, scenario, groupCtl) {
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_statistics_chart_builder.html',
      controller: 'mnStatisticsNewChartBuilderController as builderCtl',
      resolve: {
        scenario: mnHelper.wrapInFunction(scenario),
        chart: mnHelper.wrapInFunction(),
        group: mnHelper.wrapInFunction(group)
      }
    }).result.then(function () {
      mnUserRolesService.saveDashboard();
      groupCtl.maybeShowItemsControls();
    });
  }

  function onSelectNode(selectedHostname) {
    $state.go('^.statistics', {
      statsHostname: selectedHostname.indexOf("All Server Nodes") > -1 ? "all" :selectedHostname
    });
  }

  function onBucketChange(bucket) {
    $state.go('^.statistics', {
      scenarioBucket: bucket
    });
  }

  function onSelectScenario(scenarioId) {
    $state.go('^.statistics', {
      scenario: scenarioId,
    });
  }

  function onSelectZoom() {
    $state.go('^.statistics', {
      scenarioZoom: vm.zoom
    });
  }

  function initItemsDropdownSelect() {
    if ($scope.rbac.cluster.tasks.read) {
      new mnPoller($scope, function () {
        return mnTasksDetails.get().then(function (rv) {
          if (!$state.params.scenarioBucket) {
            return;
          }
          return rv.tasksXDCR.filter(function (row) {
            return row.source == $state.params.scenarioBucket;
          });
        });
      })
        .setInterval(10000)
        .subscribe("xdcrItems", vm)
        .reloadOnScopeEvent("reloadXdcrPoller")
        .cycle();
    }

    if ($scope.rbac.cluster.settings.fts && $scope.rbac.cluster.settings.fts.read) {
      new mnPoller($scope, function () {
        return $http.get('/_p/fts/api/index').then(function(rv) {
          return Object.keys(rv.data.indexDefs.indexDefs).reduce(function (acc, key) {
            var index = rv.data.indexDefs.indexDefs[key];
            if (index.sourceName == $state.params.scenarioBucket) {
              acc.push(index);
            }
            return acc;
          }, []);
        });
      })
        .setInterval(10000)
        .subscribe("ftsItems", vm)
        .reloadOnScopeEvent("reloadXdcrPoller")
        .cycle();
    }

    if ($scope.rbac.cluster.bucket['.'].n1ql.index.read) {
      new mnPoller($scope, function () {
        return mnGsiService.getIndexStatus().then(function (rv) {
          if (!$state.params.scenarioBucket) {
            return;
          }
          return rv.indexes.filter(index => index.bucket === $state.params.scenarioBucket);
        });
      })
        .setInterval(10000)
        .subscribe("indexItems", vm)
        .reloadOnScopeEvent("indexStatusURIChanged")
        .cycle();
    }

    if ($scope.rbac.cluster.bucket['.'].views.read) {
      new mnPoller($scope, function () {
        return mnStatisticsNewService.getStatsDirectory($state.params.scenarioBucket, {})
          .then(function (rv) {
            if (!$state.params.scenarioBucket) {
              return;
            }
            return rv.data.blocks.filter(function (block) {
              if (block.blockName.includes("View Stats")) {
                block.statId = block.blockName.split(": ")[1];
                var name = block.stats[0].name.split("/");
                name.pop()
                block.statKeyPrefix = name.join("/") + "/";
                return true;
              }
            });
          });
      })
        .setInterval(10000)
        .subscribe("viewItems", vm)
        .reloadOnScopeEvent("reloadViewsPoller")
        .cycle();
    }
  }

  function getSelectedScenario() {
    return vm.scenariosById && vm.scenariosById[vm.scenarioId] || {};
  }

  function activate() {
    initItemsDropdownSelect();

    mnStatisticsNewService.mnAdminStatsPoller.heartbeat.setInterval(
      mnStatisticsNewService.defaultZoomInterval(vm.zoom));

    if ($scope.rbac.cluster.stats.read) {
      mnUserRolesService.getUserProfile().then(function (profile) {
        vm.scenarioId =
          $state.params.scenario ?
          $state.params.scenario :
          mnStoreService.store("scenarios").share().find(function (item) {
            return item.name === "Cluster Overview";
          }).id || mnStoreService.store("scenarios").last().id
      });

      function groupById(arr) {
        return arr.reduce((acc, item) => {
          acc[item.id] = item;
          return acc;
        }, {});
      }

      new mnPoller($scope, function () {
        return mnUserRolesService.getUserProfile();
      })
        .setInterval(10000)
        .subscribe(function () {
          vm.scenarios = mnStoreService.store("scenarios").share();
          vm.scenariosById = groupById(vm.scenarios);
          vm.groupsById = groupById(mnStoreService.store("groups").share());
          vm.chartsById = groupById(mnStoreService.store("charts").share());
        })
        .reloadOnScopeEvent("scenariosChanged")
        .cycle();
    }

    new mnPoller($scope, function () {
      return mnStatisticsNewService.prepareNodesList($state.params);
    })
      .subscribe("nodes", vm)
      .reloadOnScopeEvent("nodesChanged")
      .cycle();
  }
}
