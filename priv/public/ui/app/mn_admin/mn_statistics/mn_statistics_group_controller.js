(function () {
  "use strict";

  angular
    .module('mnStatisticsNew')
    .controller('mnGroupDialogController', mnGroupDialogController)

  function mnGroupDialogController($uibModalInstance, mnUserRolesService, mnPromiseHelper, scenario, mnStoreService) {
    var vm = this;
    vm.group = {
      name: "",
      desc: "",
      charts: []
    };

    vm.submit = submit;

    function submit() {
      scenario.groups.push(mnStoreService.store("groups").add(vm.group).id);

      mnPromiseHelper(vm, mnUserRolesService.saveDashboard(), $uibModalInstance)
        .showGlobalSpinner()
        .showGlobalSuccess("Group added successfully!")
        .closeModal();
    }
  }

})();
