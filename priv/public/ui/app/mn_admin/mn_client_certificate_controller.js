import angular from "/ui/web_modules/angular.js";
import mnSpinner from "/ui/app/components/directives/mn_spinner.js";
import mnClientCertificateService from "./mn_client_certificate_service.js"

export default "mnClientCertificate";

angular
  .module("mnClientCertificate", [mnClientCertificateService, mnSpinner])
  .controller("mnClientCertController", mnClientCertController);

function mnClientCertController($scope, mnClientCertificateService, mnPromiseHelper) {
  var vm = this;
  vm.onSubmit = onSubmit;

  activate();

  function maybeSetInititalValue(array, value) {
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
        if ($scope.rbac.cluster.admin.security.write && vm.settings.prefixes.length === 0) {
          vm.settings.prefixes.push({delimiter: '', prefix: '', path: 'subject.cn'});
        }
      });
  }
}
