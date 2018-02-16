(function () {
  "use strict";

  angular
    .module("mnClientCertificate", [
      "mnClientCertificateService",
      "mnSpinner"
    ])
    .controller("mnClientCertController", mnClientCertController);


  function mnClientCertController($scope, mnClientCertificateService, mnPromiseHelper) {
    var vm = this;
    vm.onSubmit = onSubmit;

    activate();

    function maybeSetInititalValue(array, value) {
      if (array.length === 0 || !_.isEqual(value, array[0])) {
        array.push(value);
      }
    }

    function onSubmit() {
      if ($scope.mnGlobalSpinnerFlag) {
        return;
      }

      mnPromiseHelper(vm, mnClientCertificateService.postClientCertificateSettings(vm.settings))
        .showGlobalSpinner()
        .catchErrors()
        .showGlobalSuccess("Settings saved successfully!");
    }

    function activate() {
      mnPromiseHelper(vm, mnClientCertificateService.getClientCertificateSettings())
        .applyToScope("settings")
        .onSuccess(function (resp) {
          if ($scope.rbac.cluster.admin.security.write) {
            maybeSetInititalValue(vm.settings.prefixes, {delimiter: '', prefix: '', path: ''});
          }
        });
    }
  }
})();
