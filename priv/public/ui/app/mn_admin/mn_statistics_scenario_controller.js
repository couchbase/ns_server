export default mnScenarioDialogController;

function mnScenarioDialogController($scope, $rootScope, mnStatisticsNewService, mnUserRolesService, $state, $document, $uibModal, mnStoreService) {
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
      groups: []
    };
  }

  function clear() {
    setEmptyScenario();
    vm.copyScenario = "true";
    vm.isEditingMode = false;
    vm.showRestOfMenu = false;
  }

  function deleteScenario(scenarioID) {
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_statistics_scenario_delete.html',
    }).result.then(function () {
      mnStatisticsNewService.deleteScenario(scenarioID);
      mnUserRolesService.saveDashboard().then(() => {
        $rootScope.$broadcast("scenariosChanged");
        selectLastScenario();
      });
    });
  }

  function editScenario(scenario) {
    vm.isEditingMode = !!scenario;
    vm.scenario = Object.assign({}, scenario);
    vm.showRestOfMenu = true;
  }

  function selectLastScenario() {
    $scope.statisticsNewCtl.scenarioId = mnStoreService.store("scenarios").last().id;
    return $state.go("^.statistics", {
      scenario: mnStoreService.store("scenarios").last().id
    });
  }

  function onSubmit(currentScenario) {
    if (!vm.scenario.name) {
      return;
    }

    if (vm.isEditingMode) {
      mnStoreService.store("scenarios").put(vm.scenario);
    } else {
      if (vm.copyScenario == "true") {
        mnStatisticsNewService.copyScenario(vm.scenario,
                                            currentScenario);
      } else {
        mnStoreService.store("scenarios").add(vm.scenario);
      }
      selectLastScenario();
    }

    mnUserRolesService.saveDashboard().then(() => {
      $rootScope.$broadcast("scenariosChanged");
      $document.triggerHandler("click");
      clear();
    });
  }
}
