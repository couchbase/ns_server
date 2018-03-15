(function () {
  "use strict";

  angular
    .module('mnServers')
    .controller('mnMultipleFailoverDialogController', mnMultipleFailoverDialogController);

  function mnMultipleFailoverDialogController($scope, mnPoolDefault, mnServersService, mnPromiseHelper, groups, nodes, $uibModalInstance, $uibModal) {
    var vm = this;

    vm.nodes = nodes;
    vm.onSubmit = onSubmit;
    vm.mnGroups = groups;
    vm.mnFilteredNodesHolder = {nodes: []};

    function doPostFailover(allowUnsafe) {
      var otpNodes = _.map(_.filter(vm.mnFilteredNodesHolder.nodes, {isSelected: true}), 'otpNode');
      var promise = mnServersService.postFailover("failOver", otpNodes, allowUnsafe);
      return mnPromiseHelper(vm, promise, $uibModalInstance)
        .showGlobalSpinner()
        .catchErrors()
        .closeOnSuccess()
        .broadcast("reloadServersPoller");
    }

    function onSubmit() {
      doPostFailover()
        .getPromise()
        .then(null, function (resp) {
          if (resp.status == 504) {
            return $uibModal.open({
              templateUrl: 'app/mn_admin/mn_servers/failover_dialog/mn_servers_failover_confirmation_dialog.html'
            }).result.then(function () {
              return doPostFailover(true);
            });
          }
        });
    }
  }
})();
