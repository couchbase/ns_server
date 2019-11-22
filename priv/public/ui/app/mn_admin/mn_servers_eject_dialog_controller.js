export default mnServersEjectDialogController;

function mnServersEjectDialogController($rootScope, $uibModalInstance, node, warnings, mnServersService) {
  var vm = this;
  vm.warningFlags = warnings;
  vm.doEjectServer = doEjectServer;

  function doEjectServer() {
    mnServersService.addToPendingEject(node);
    $uibModalInstance.close();
    $rootScope.$broadcast("reloadNodes");
  };
}
