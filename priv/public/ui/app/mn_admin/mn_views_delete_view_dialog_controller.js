export default mnViewsDeleteViewDialogController;

function mnViewsDeleteViewDialogController($state, $uibModalInstance, mnPromiseHelper, mnViewsListService, currentDdocName, currentViewName) {
  var vm = this;
  vm.currentDdocName = currentDdocName;
  vm.currentViewName = currentViewName;
  vm.doDelete = doDelete;

  function doDelete() {
    var url = mnViewsListService.getDdocUrl($state.params.bucket, currentDdocName);

    var promise = mnViewsListService.getDdoc(url).then(function (presentDdoc) {
      delete presentDdoc.json['views'][currentViewName];
      return mnViewsListService.createDdoc(url, presentDdoc.json);
    });

    mnPromiseHelper(vm, promise, $uibModalInstance)
      .showGlobalSpinner()
      .closeFinally()
      .broadcast("reloadViewsPoller")
      .showGlobalSuccess("View deleted successfully!");
  };
}
