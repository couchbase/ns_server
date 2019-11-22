import angular from "/ui/web_modules/angular.js";

import mnSpinner from "/ui/app/components/directives/mn_spinner.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnPoorMansAlertsService from "./mn_poor_mans_alerts_service.js";

export default "mnPoorMansAlerts";

angular
  .module("mnPoorMansAlerts", [
    mnSpinner,
    mnPromiseHelper,
    mnPoorMansAlertsService
  ])
  .controller("mnPoorMansAlertsController", mnPoorMansAlertsController);

function mnPoorMansAlertsController(mnPromiseHelper, mnPoorMansAlertsService, alertsSilenceURL, alerts, $uibModalInstance) {
  var vm = this;

  vm.alerts = alerts;
  vm.onClose = onClose;

  function onClose() {
    mnPromiseHelper(vm, mnPoorMansAlertsService.postAlertsSilenceURL(alertsSilenceURL), $uibModalInstance)
      .showGlobalSpinner()
      .closeOnSuccess();
  }
}
