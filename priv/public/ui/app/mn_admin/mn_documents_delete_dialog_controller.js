export default mnDocumentsDeleteDialogController;

function mnDocumentsDeleteDialogController(mnDocumentsEditingService, $state, documentId, $uibModalInstance, mnPromiseHelper) {
  var vm = this;
  vm.onSubmit = onSubmit;

  function onSubmit() {
    var promise = mnDocumentsEditingService.deleteDocument({
      bucket: $state.params.bucket,
      documentId: documentId
    });

    mnPromiseHelper(vm, promise, $uibModalInstance)
      .showGlobalSpinner()
      .closeFinally()
      .broadcast("reloadDocumentsPoller")
      .showGlobalSuccess("Document deleted successfully!");
  }
}
