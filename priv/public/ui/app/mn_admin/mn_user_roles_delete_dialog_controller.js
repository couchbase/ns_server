export default mnUserRolesDeleteDialogController;

function mnUserRolesDeleteDialogController(mnUserRolesService, user, mnPromiseHelper, $uibModalInstance) {
  var vm = this;
  vm.username = user.id;
  vm.onSubmit = onSubmit;

  function onSubmit() {
    mnPromiseHelper(vm, mnUserRolesService.deleteUser(user), $uibModalInstance)
      .showGlobalSpinner()
      .closeFinally()
      .broadcast("reloadRolesPoller")
      .showGlobalSuccess("User deleted successfully!");
  }
}
