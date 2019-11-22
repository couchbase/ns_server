import angular from "/ui/web_modules/angular.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnSpinner from "/ui/app/components/directives/mn_spinner.js";

import mnRootCertificateService from "./mn_root_certificate_service.js";

export default "mnRootCertificate";

angular
  .module("mnRootCertificate", [
    mnRootCertificateService,
    mnPromiseHelper,
    mnSpinner
  ])
  .controller("mnRootCertificateController", mnRootCertificateController);

function mnRootCertificateController(mnRootCertificateService, mnPromiseHelper) {
  var vm = this;

  activate();

  function activate() {
    mnPromiseHelper(vm, mnRootCertificateService.getDefaultCertificate())
      .applyToScope("certificate");
  }
}
