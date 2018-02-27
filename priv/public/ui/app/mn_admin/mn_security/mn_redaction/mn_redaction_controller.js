(function () {
  "use strict";

  angular
    .module("mnRedaction", [
      "mnRedactionService",
      "mnSpinner"
    ])
    .controller("mnRedactionController", mnRedactionController);


  function mnRedactionController($scope, mnRedactionService, mnPromiseHelper) {
    var vm = this;
    vm.onSubmit = onSubmit;

    activate();

    function maybeSetInititalValue(array, value) {
    }

    function onSubmit() {
      if ($scope.mnGlobalSpinnerFlag) {
        return;
      }

      mnPromiseHelper(vm, mnRedactionService.postRedactionSettings(vm.settings))
        .showGlobalSpinner()
        .catchErrors()
        .showGlobalSuccess("Settings saved successfully!");
    }

    function activate() {
      mnPromiseHelper(vm, mnRedactionService.getRedactionSettings())
        .applyToScope("settings")
        .onSuccess(function (resp) {
          if ($scope.rbac.cluster.admin.security.write && vm.settings.prefixes.length === 0) {
            vm.settings.prefixes.push({delimiter: '', prefix: '', path: ''});
          }
        });
    }
  }
})();
