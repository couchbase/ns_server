(function () {
  "use strict";

  angular
    .module('mnServers')
    .controller('mnServersAddDialogController', mnServersAddDialogController)

  function mnServersAddDialogController($scope, $rootScope, $q, $uibModal, mnServersService, $uibModalInstance, mnHelper, mnPromiseHelper, groups) {
    var vm = this;

    vm.addNodeConfig = {
      services: {
        model: {
          kv: true,
          index: true,
          n1ql: true,
          fts: true
        }
      },
      credentials: {
        hostname: '',
        user: 'Administrator',
        password: ''
      }
    };
    if ($scope.poolDefault.isEnterprise) {
      vm.addNodeConfig.services.model.cbas = true;
      vm.addNodeConfig.services.model.eventing = true;
      vm.addNodeConfig.services.model.mobile = true;
    }
    vm.isGroupsAvailable = !!groups;
    vm.onSubmit = onSubmit;
    if (vm.isGroupsAvailable) {
      vm.addNodeConfig.selectedGroup = groups.groups[0];
      vm.groups = groups.groups;
    }

    activate();

    function activate() {
      reset();
    }
    function reset() {
      vm.focusMe = true;
    }
    function onSubmit(form) {
      if (vm.viewLoading) {
        return;
      }

      var servicesList = mnHelper.checkboxesToList(vm.addNodeConfig.services.model);

      form.$setValidity('services', !!servicesList.length);

      if (form.$invalid) {
        return reset();
      }

      var promise = mnServersService.addServer(vm.addNodeConfig.selectedGroup, vm.addNodeConfig.credentials, servicesList);

      mnPromiseHelper(vm, promise, $uibModalInstance)
        .showGlobalSpinner()
        .catchErrors()
        .closeOnSuccess()
        .broadcast("reloadServersPoller")
        .broadcast("maybeShowMemoryQuotaDialog", vm.addNodeConfig.services.model)
        .showGlobalSuccess("Server added successfully!");
    };
  }
})();
