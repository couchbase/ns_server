(function () {
  "use strict";

  angular
    .module('mnStatisticsNew')
    .controller('mnScenarioDialogController', mnScenarioDialogController)

  function mnScenarioDialogController(scenario, $uibModalInstance, mnStatisticsNewService, $state) {
    var vm = this;

    vm.scenario = scenario ? Object.assign({}, scenario) : {
      name: "",
      desc: "",
      zoom: "hour",
      groups: []
    };

    vm.isNew = !vm.scenario.name;
    vm.submit = submit;

    function submit(doDelete) {
      mnStatisticsNewService.addUpdateScenario(vm.scenario, doDelete).then(function () {
        $uibModalInstance.close();
        var scenarios = mnStatisticsNewService.export.scenarios;
        scenarios.selected = scenarios[scenarios.length - 1];
        $state.go("^.statistics", {
          scenario: vm.scenario.id,
          openedScenarios: []
        });
      });
    }
  }

})();
