export default mnRolesGroupsDeleteDialogController;

function mnRolesGroupsDeleteDialogController(mnUserRolesService, rolesGroup, mnPromiseHelper, $uibModalInstance) {
  var vm = this;
  vm.grolesGroupsId = rolesGroup.id;
  vm.onSubmit = onSubmit;

  function onSubmit() {
    mnPromiseHelper(vm, mnUserRolesService.deleteRolesGroup(rolesGroup), $uibModalInstance)
      .showGlobalSpinner()
      .closeFinally()
      .broadcast("reloadRolesGroupsPoller")
      .showGlobalSuccess("Group deleted successfully!");
  }
}
