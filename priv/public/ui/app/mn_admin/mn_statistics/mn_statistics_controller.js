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

  function mnStatisticsNewController($scope, mnStatisticsNewService, $state, $http, mnPoller, mnBucketsService, $uibModal, $rootScope, mnHelper, $window, mnUserRolesService, permissions) {
    var vm = this;

    vm.onSelectScenario = onSelectScenario;
    vm.onSelectZoom = onSelectZoom;

    vm.statisticsService = mnStatisticsNewService.export;
    vm.saveScenarios = mnStatisticsNewService.saveScenarios;

    if (vm.statisticsService.scenarios.selected) {
      $state.go("^.statistics", {
        scenario: vm.statisticsService.scenarios.selected.id,
      });
    }

    vm.currentBucket = $state.params.statisticsBucket;
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

    function openChartBuilderDialog() {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder.html',
        controller: 'mnStatisticsNewChartBuilderController as chartBuilderCtl',
        resolve: {
          chart: mnHelper.wrapInFunction()
        }
      });
    }

    function deleteGroup(group) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_scenario_delete.html',
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

    function onSelectZoom(zoom) {
      mnStatisticsNewService.saveScenarios().then(function () {
        $state.go('^.statistics', {
          zoom: zoom
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
