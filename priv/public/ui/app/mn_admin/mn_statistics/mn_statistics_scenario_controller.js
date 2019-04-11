(function () {
  "use strict";

  angular
    .module('mnStatisticsNew')
    .controller('mnScenarioDialogController', mnScenarioDialogController)

  function mnScenarioDialogController(mnStatisticsNewService, $state, $document, $uibModal, mnHelper) {
    var vm = this;

    vm.editScenario = editScenario;
    vm.deleteScenario = deleteScenario;
    vm.onSubmit = onSubmit;
    vm.copyScenario = "true";
    vm.clear = clear;

    setEmptyScenario();

    function setEmptyScenario() {
      vm.scenario = {
        name: "",
        desc: "",
        groups: [{
          id: mnHelper.generateID(),
          name: "click to edit group name",
          desc: "",
          charts: []
        }]
      };
    }

    function clear() {
      setEmptyScenario();
      vm.copyScenario = "true";
      vm.isEditingMode = false;
      vm.showRestOfMenu = false;
    }

    function deleteScenario(scenario) {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_scenario_delete.html',
      }).result.then(function () {
        return mnStatisticsNewService.deleteScenario(scenario).then(selectLastScenario);
      });
    }

    function editScenario(scenario) {
      vm.isEditingMode = !!scenario;
      vm.scenario = Object.assign({}, scenario);
      vm.showRestOfMenu = true;
    }

    function selectLastScenario() {
      var scenarios = mnStatisticsNewService.export.scenarios;
      scenarios.selected = scenarios[scenarios.length - 1];
      return $state.go("^.statistics", {
        scenario: scenarios.selected.id
      });
    }

    function onSubmit() {
      if (!vm.scenario.name) {
        return;
      }
      var selected = mnStatisticsNewService.export.scenarios.selected;
      if ((vm.copyScenario == "true") && selected && !vm.isEditingMode) {
        var groups = vm.scenario.groups;
        vm.scenario.groups = selected.groups.map(function (group, index) {
          group = Object.assign({}, group);
          group.id = mnHelper.generateID();
          group.preset = false;
          group.charts = group.charts.map(function (chart, index) {
            chart = Object.assign({}, chart);
            chart.preset = false;
            chart.group = group.id
            chart.id = mnHelper.generateID();
            return chart;
          });
          return group;
        });
      }

      mnStatisticsNewService.addUpdateScenario(vm.scenario)
        .then(vm.isEditingMode ? clear : function () {
          selectLastScenario();
          $document.triggerHandler("click");
        });
    }
  }

})();
