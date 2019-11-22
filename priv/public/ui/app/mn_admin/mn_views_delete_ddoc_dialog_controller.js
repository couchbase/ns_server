export default mnViewsDeleteDdocDialogController;

function mnViewsDeleteDdocDialogController($state, $uibModalInstance, mnViewsListService, currentDdocName, mnPromiseHelper) {
  var vm = this;
  vm.currentDdocName = currentDdocName;
  vm.doDelete = doDelete;

  function doDelete() {
    var url = mnViewsListService.getDdocUrl($state.params.bucket, currentDdocName);
    var promise = mnViewsListService.deleteDdoc(url);
    mnPromiseHelper(vm, promise, $uibModalInstance)
      .showGlobalSpinner()
      .closeFinally()
      .broadcast("reloadViewsPoller")
      .showGlobalSuccess("Design document deleted successfully!");
  }
}
