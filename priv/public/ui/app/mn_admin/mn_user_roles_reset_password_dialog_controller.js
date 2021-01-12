export default mnUserRolesResetPasswordDialogController;

function mnUserRolesResetPasswordDialogController(mnUserRolesService, $uibModalInstance, mnPromiseHelper, user) {
  var vm = this;

  vm.user = user;
  vm.userID = vm.user.id;
  vm.save = save;

  function save() {
    if (vm.form.$invalid) {
      return;
    }
    mnPromiseHelper(vm, mnUserRolesService.addUser(
      vm.user,
      vm.user.roles.map(function (role) {
        if (role.bucket_name) {
          let params = ([role.bucket_name,
                         role.scope_name,
                         role.collection_name]).filter(v => v);
          return role.role + '[' + mnUserRolesService.packRoleParams(params) + ']';
        } else {
          return role.role;
        }
      }),
      vm.user.groups,
      true,
      true
    ), $uibModalInstance)
      .showGlobalSpinner()
      .catchErrors()
      .broadcast("reloadRolesPoller")
      .closeOnSuccess()
      .showGlobalSuccess("Password reset successfully!");
  }
}
