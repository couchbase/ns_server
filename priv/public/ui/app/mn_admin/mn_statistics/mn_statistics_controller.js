(function () {
  "use strict";

  angular
    .module('mnStatisticsNew', [
      'mnStatisticsNewService',
      'mnStatisticsDescriptionService',
      'mnPoll',
      'mnBucketsService',
      'mnHelper',
      'ui.router',
      'ui.bootstrap',
      'nvd3',
      'mnBucketsStats',
      'mnSpinner',
      'mnStatisticsChart',
      'mnUserRolesService',
      'mnFilters',
      'mnStoreService'
    ])
    .controller('mnStatisticsNewController', mnStatisticsNewController)
    .controller('mnStatisticsGroupsController', mnStatisticsGroupsController)
    .controller('mnStatisticsChartsController', mnStatisticsChartsController);

  function mnStatisticsChartsController($scope, $rootScope, $uibModal, mnStatisticsNewService, mnStoreService, mnHelper, mnUserRolesService, $state, $timeout) {
    var vm = this;

    vm.deleteChart = deleteChart;
    vm.editChart = editChart;
    vm.getNvd3Options = getNvd3Options;
    vm.chart = mnStoreService.store("charts").get($scope.chartID);

    function deleteChart() {
      vm.showChartControls = false;
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder_delete.html'
      }).result.then(function () {
        mnStatisticsNewService.deleteChart($scope.chartID);
        mnUserRolesService.saveDashboard();
      });
    }

    function editChart(group, scenario) {
      vm.showChartControls = false;
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder.html',
        controller: 'mnStatisticsNewChartBuilderController as chartBuilderCtl',
        resolve: {
          chart: mnHelper.wrapInFunction(vm.chart),
          group: mnHelper.wrapInFunction(group),
          scenario: mnHelper.wrapInFunction(scenario),
        }
      }).result.then(function () {
        mnUserRolesService.saveDashboard();
        vm.reloadChartDirective = true;
        $timeout(function () {
          vm.reloadChartDirective = false;
        });
      });
    }

    function getNvd3Options() {
      var units = mnStatisticsNewService.getStatsUnits(vm.chart.stats);

      return {
        showLegend: false,
        callback: function (chart) {
          if (!chart) {
            return;
          }
          chart.interactiveLayer.dispatch.on("elementClick", function () {
            if (Object.keys(units).length === 1) {
              $uibModal.open({
                templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_chart_focus_dialog.html',
                controller: 'mnStatisticsChartFocusDialogController as chartFocusDialogCtl',
                windowTopClass: "chart-overlay",
                resolve: {
                  chartConfig: mnHelper.wrapInFunction(vm.chart)
                }
              });
            } else {
              var scope = $rootScope.$new();
              scope.config = vm.chart;
              scope.bucket = $state.params.scenarioBucket;
              scope.zoom = $state.params.scenarioZoom;
              $uibModal.open({
                templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_chart_dialog.html',
                scope: scope,
                windowTopClass: "chart-overlay"
              });
            }
          });
        }
      };
    }
  }

  function mnStatisticsGroupsController($scope, $uibModal,
                                        mnStatisticsNewService, mnStoreService, mnUserRolesService) {
    var vm = this;
    vm.isDetailsOpened = true;
    vm.hideGroupControls = hideGroupControls;
    vm.onGroupNameBlur = onGroupNameBlur;
    vm.onGroupFocus = onGroupFocus;
    vm.onGroupSubmit = onGroupSubmit;
    vm.onGroupDelete = onGroupDelete;
    vm.deleteGroup = deleteGroup;

    vm.group = mnStoreService.store("groups").get($scope.groupID);

    function deleteGroup(groupID) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_group_delete.html',
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
      vm.initName = vm.group.name;
      mnUserRolesService.saveDashboard()
      hideGroupControls();
      vm.focusOnSubmit = true;
    }

    function onGroupFocus() {
      vm.showGroupControls = true;
      vm.initName = vm.group.name;
    }

    function onGroupNameBlur() {
      if (!vm.onControlClick) {
        vm.showGroupControls = false;
        vm.group.name = vm.initName;
        mnStoreService.store("groups").put(vm.group);
      }
    }

    function hideGroupControls() {
      if (vm.onControlClick) {
        vm.onControlClick = false;
        onGroupNameBlur();
      }
    }
  }

  function mnStatisticsNewController($scope, mnStatisticsNewService, $state, $http, mnPoller, mnBucketsService, $uibModal, $rootScope, mnHelper, $window, mnUserRolesService, permissions, $timeout,mnStoreService) {
    var vm = this;

    vm.mnStatisticsNewScope = $scope;

    vm.onSelectScenario = onSelectScenario;
    vm.onSelectZoom = onSelectZoom;

    vm.bucket = $state.params.scenarioBucket;
    vm.zoom = $state.params.scenarioZoom;
    //selected scenario holder
    vm.scenario = {};
    vm.openGroupDialog = openGroupDialog;
    vm.selectedBucket = $state.params.scenarioBucket;
    vm.onBucketChange = onBucketChange;

    vm.openChartBuilderDialog = openChartBuilderDialog;
    vm.showBlocks = {
      "Server Resources": true
    };

    activate();

    function openGroupDialog(scenario) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_group.html',
        controller: 'mnGroupDialogController as groupDialogCtl',
        resolve: {
          scenario: mnHelper.wrapInFunction(scenario)
        }
      });
    }

    function openChartBuilderDialog(group, scenario) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder.html',
        controller: 'mnStatisticsNewChartBuilderController as chartBuilderCtl',
        resolve: {
          scenario: mnHelper.wrapInFunction(scenario),
          chart: mnHelper.wrapInFunction(),
          group: mnHelper.wrapInFunction(group)
        }
      }).result.then(function () {
        mnUserRolesService.saveDashboard();
      });
    }

    function onBucketChange(bucket) {
      $state.go('^.statistics', {
        scenarioBucket: bucket
      });
    }

    function onSelectScenario(scenario) {
      $state.go('^.statistics', {
        scenario: scenario.id,
      });
    }

    function onSelectZoom() {
      $state.go('^.statistics', {
        scenarioZoom: vm.zoom
      });
    }

    function activate() {
      if ($scope.rbac.cluster.stats.read) {
        mnUserRolesService.getUserProfile().then(function (profile) {
          vm.scenario.selected =
            $state.params.scenario ?
            mnStoreService.store("scenarios").get($state.params.scenario) :
            mnStoreService.store("scenarios").last();
          vm.scenarios = mnStoreService.store("scenarios").share();
        });
      }

      new mnPoller($scope, function () {
        return mnStatisticsNewService.prepareNodesList($state.params);
      })
        .subscribe("nodes", vm)
        .reloadOnScopeEvent("nodesChanged")
        .cycle();
    }
  }
})();
