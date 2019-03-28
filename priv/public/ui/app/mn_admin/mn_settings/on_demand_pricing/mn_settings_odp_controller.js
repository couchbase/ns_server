(function () {
  "use strict";

  angular.module('mnSettingsOnDemandPricing', [
    'mnSettingsODPService',
    'mnHelper',
    'mnPromiseHelper',
    "mnSettingsClusterService"
  ]).controller('mnSettingsODPController', mnSettingsODPController);

  function mnSettingsODPController($scope, $q, mnHelper, mnPromiseHelper, mnSettingsODPService, mnPoolDefault, mnSettingsClusterService) {
    var odpc = this;
    odpc.reporting_enabled = false;
    odpc.contract_id = '';
    odpc.customer_token = '';
    odpc.valid = null;
    odpc.validation_error = null;

    mnSettingsClusterService.registerSubmitCallback(submit);

    activate();

    function activate() {
      if (mnPoolDefault.export.compat.atLeast65) {
        mnPromiseHelper(odpc, mnSettingsODPService.getODPSettings())
          .applyToScope(function (resp) {

            odpc.reporting_enabled = resp.data.reporting_enabled;
            odpc.contract_id = resp.data.contract_id;
            odpc.customer_token = resp.data.customer_token;

            // if the feature is turned on, get the validation status
            if (odpc.reporting_enabled)
              validate();
          });
      }
    }

    function submit() {

      var promise = mnSettingsODPService.saveODPSettings(odpc.reporting_enabled,odpc.contract_id,odpc.customer_token);
      promise.then(
          function success(resp) {
            validate();
          },
          function error(resp) {
            console.log("ODP Save Error! " + JSON.stringify(resp));
          }
      );
      return(promise);
    }

    function validate() {
      odpc.valid = null;
      odpc.validation_results = null;

      var promise = mnSettingsODPService.validateODPSettings(odpc.reporting_enabled,odpc.contract_id,odpc.customer_token);
      promise.then(
          function success(resp) {
            // we only care about errors if the feature is on
            if (odpc.reporting_enabled && resp.data)
              odpc.valid = resp.data.validation;
          },
          function error(resp) {
            // we only care about errors if the feature is on
            if (odpc.reporting_enabled) {
              odpc.valid = false;
              odpc.validation_error = resp.data;
            }
          }
      );
      return(promise);
    }
  }
})();
