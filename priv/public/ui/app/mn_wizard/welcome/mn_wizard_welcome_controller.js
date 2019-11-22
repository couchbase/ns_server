export default mnWizardWelcomeController;

function mnWizardWelcomeController(pools, mnWizardService) {
  var vm = this;

  vm.implementationVersion = pools.implementationVersion;
  vm.setIsNewClusterFlag = setIsNewClusterFlag;

  function setIsNewClusterFlag(value) {
    mnWizardService.getState().isNewCluster = value;
  }
}
