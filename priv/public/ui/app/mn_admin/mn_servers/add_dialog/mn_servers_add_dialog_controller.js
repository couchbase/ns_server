(function () {
  "use strict";

  angular
    .module('mnServers')
    .controller('mnServersAddDialogController', mnServersAddDialogController)

  function mnServersAddDialogController($scope, $rootScope, $q, $uibModal, mnServersService, $uibModalInstance, mnHelper, mnPromiseHelper, groups, mnClusterConfigurationService, mnPoolDefault) {
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
      mnClusterConfigurationService.getSelfConfig().then(function (selfConfig) {
        var rv = {};
        rv.selfConfig = selfConfig;
        if ($scope.poolDefault.isEnterprise) {
          rv.cbasDirs = selfConfig.storage.hdd[0].cbas_dirs;
        }
        rv.dbPath = selfConfig.storage.hdd[0].path;
        rv.indexPath = selfConfig.storage.hdd[0].index_path;
        vm.selfConfig = rv;
      });
    }
    function postDiskStorage(resp) {
      if (resp) {
        vm.optNode = resp.otpNode;
      }
      var data = {
        path: vm.selfConfig.dbPath,
        index_path: vm.selfConfig.indexPath
      };
      if ($scope.poolDefault.isEnterprise) {
        data.cbas_path = vm.selfConfig.cbasDirs;
      }
      var promise = mnClusterConfigurationService.postDiskStorage(data, vm.optNode);
      return mnPromiseHelper(vm, promise)
        .catchErrors('postDiskStorageErrors')
        .getPromise();
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
      var promise = postDiskStorage().then(function () {
        return mnServersService.addServer(vm.addNodeConfig.selectedGroup,
                                          vm.addNodeConfig.credentials,
                                          servicesList);
      });

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
