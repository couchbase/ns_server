(function () {
  "use strict";

  angular
    .module('mnStatisticsNew')
    .controller('mnGroupDialogController', mnGroupDialogController)

  function mnGroupDialogController($uibModalInstance, mnStatisticsNewService, mnPromiseHelper) {
    var vm = this;
    vm.group = {
      name: "",
      desc: "",
      charts: []
    };

    vm.submit = submit;

    function submit() {
      mnPromiseHelper(vm, mnStatisticsNewService.addUpdateGroup(vm.group), $uibModalInstance)
        .showGlobalSpinner()
        .showGlobalSuccess("Group added successfully!")
        .closeModal();
    }
  }

})();
