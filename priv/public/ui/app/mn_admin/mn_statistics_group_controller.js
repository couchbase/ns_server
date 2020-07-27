export default mnGroupDialogController;

function mnGroupDialogController($rootScope, $uibModalInstance, mnUserRolesService, mnPromiseHelper, scenarioId, mnStoreService) {
  var vm = this;
  vm.group = {
    name: "",
    desc: "",
    charts: [],
    isOpen: true
  };

  vm.submit = submit;

  function submit() {
    var group = mnStoreService.store("groups").add(vm.group);
    mnStoreService.store("scenarios")
      .share()
      .find(scenario => scenario.id === scenarioId)
      .groups.push(group.id);

    mnPromiseHelper(vm, mnUserRolesService.saveDashboard())
      .showGlobalSpinner()
      .showGlobalSuccess("Group added successfully!")
      .onSuccess(function () {
        $rootScope.$broadcast("scenariosChanged");
        $uibModalInstance.close(group);
      });
  }
}
