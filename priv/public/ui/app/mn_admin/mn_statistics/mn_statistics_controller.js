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
      'mnUserRolesService'
    ])
    .controller('mnStatisticsNewController', mnStatisticsNewController);

  function mnStatisticsNewController($scope, mnStatisticsNewService, $state, $http, mnPoller, mnBucketsService, $uibModal, $rootScope, mnHelper, $window, mnUserRolesService, permissions, $timeout, $document) {
    var vm = this;

    vm.onSelectScenario = onSelectScenario;
    vm.onSelectZoom = onSelectZoom;
    vm.$document = $document;

    vm.statisticsService = mnStatisticsNewService.export;
    vm.saveScenarios = mnStatisticsNewService.saveScenarios;
    vm.bucket = $state.params.scenarioBucket;
    vm.zoom = $state.params.scenarioZoom;
    vm.getNvd3Options = getNvd3Options;
    vm.editChart = editChart;
    vm.deleteChart = deleteChart;

    vm.hideGroupControls = hideGroupControls;
    vm.onGroupNameBlur = onGroupNameBlur;

    if (vm.statisticsService.scenarios.selected) {
      $state.go("^.statistics", {
        scenario: vm.statisticsService.scenarios.selected.id,
      });
    }

    vm.openGroupDialog = openGroupDialog;
    vm.openScenarioDialog = openScenarioDialog;
    vm.deleteGroup = deleteGroup;

    vm.selectedBucket = $state.params.scenarioBucket;
    vm.onBucketChange = onBucketChange;

    vm.openChartBuilderDialog = openChartBuilderDialog;
    vm.showBlocks = {
      "Server Resources": true
    };

    activate();

    function deleteChart(config) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder_delete.html',
        scope: $scope
      }).result.then(function () {
        var group = _.find(mnStatisticsNewService.export.scenarios.selected.groups,
                           {'id': config.group});
        var index = _.findIndex(group.charts, {'id': config.id});
        group.charts.splice(index, 1);
        mnStatisticsNewService.saveScenarios();
      });
    }

    function editChart(config) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder.html',
        controller: 'mnStatisticsNewChartBuilderController as chartBuilderCtl',
        resolve: {
          chart: mnHelper.wrapInFunction(config),
          group: mnHelper.wrapInFunction()
        }
      }).result.then(function () {
        $state.reload();
      });
    }

    function getNvd3Options(config) {
      var units = mnStatisticsNewService.getStatsUnits(config.stats);

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
                  chartConfig: mnHelper.wrapInFunction(config)
                }
              });
            } else {
              var scope = $rootScope.$new();
              scope.config = config;
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

    function onGroupNameBlur(scope, group) {
      if (!scope.onControlClick) {
        scope.showGroupControls = false;
        group.name = scope.initName;
      }
    }

    function hideGroupControls(scope, group) {
      if (scope.onControlClick) {
        scope.onControlClick = false;
        onGroupNameBlur(scope, group);
      }
    }

    function openScenarioDialog(scenario) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_scenario.html',
        controller: 'mnScenarioDialogController as scenarioDialogCtl',
        resolve: {
          scenario: mnHelper.wrapInFunction(scenario)
        }
      });
    }

    function openGroupDialog() {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_group.html',
        controller: 'mnGroupDialogController as groupDialogCtl',
      });
    }

    function openChartBuilderDialog(group) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder.html',
        controller: 'mnStatisticsNewChartBuilderController as chartBuilderCtl',
        resolve: {
          chart: mnHelper.wrapInFunction(),
          group: mnHelper.wrapInFunction(group)
        }
      });
    }

    function deleteGroup(group) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_group_delete.html',
      }).result.then(function () {
        mnStatisticsNewService.deleteGroup(group);
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
      mnStatisticsNewService.saveScenarios().then(function () {
        $state.go('^.statistics', {
          scenarioZoom: vm.zoom
        });
      });
    }

    function activate() {
      if ($scope.rbac.cluster.stats.read) {
        mnUserRolesService.getUserProfile().then(function (profile) {
          var scenarios = profile.scenarios;
          vm.statisticsService.scenarios = scenarios;
          vm.statisticsService.scenarios.selected =
            scenarios[$state.params.scenario ?
                      _.findIndex(scenarios,
                                  {'id': $state.params.scenario}) : 0];
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
