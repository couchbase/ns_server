export default mnGroupsDeleteDialogController;

function mnGroupsDeleteDialogController($uibModalInstance, mnGroupsService, mnPromiseHelper, group) {
  var vm = this;

  vm.onSubmit = onSubmit;

  function onSubmit() {
    if (vm.viewLoading) {
      return;
    }

    var promise = mnGroupsService.deleteGroup(group.uri);
    mnPromiseHelper(vm, promise, $uibModalInstance)
      .showGlobalSpinner()
      .catchErrors()
      .closeFinally()
      .reloadState("app.admin.servers.list.groups")
      .showGlobalSuccess("Group deleted successfully!");
  }
}
