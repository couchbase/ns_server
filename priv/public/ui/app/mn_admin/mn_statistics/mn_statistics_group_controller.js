(function () {
  "use strict";

  angular
    .module('mnStatisticsNew')
    .controller('mnGroupDialogController', mnGroupDialogController)

  function mnGroupDialogController($uibModalInstance, mnStatisticsNewService) {
    var vm = this;
    vm.group = {
      name: "",
      desc: "",
      charts: []
    };

    vm.submit = submit;

    function submit() {
      mnStatisticsNewService.addUpdateGroup(vm.group).then(function () {
        $uibModalInstance.close();
      });
    }
  }

})();
