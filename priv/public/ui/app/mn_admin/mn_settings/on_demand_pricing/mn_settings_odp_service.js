(function () {
  "use strict";

  angular.module('mnSettingsODPService', [
  ]).factory('mnSettingsODPService', mnSettingsODPServiceFactory);

  function mnSettingsODPServiceFactory($http) {
    var mnSettingsODPService = {
      getODPSettings: getODPSettings,
      saveODPSettings: saveODPSettings,
      validateODPSettings: validateODPSettings
    };

    return mnSettingsODPService;

    function getODPSettings() {
      return $http({
        method: 'GET',
        url: "/settings/license"
      });
    }

    //
    // Parameters to save:
    // - reporting_enabled
    // - contract_id
    // - customer_token
    //
    function saveODPSettings(reporting_enabled, contract_id, customer_token) {
      var request = {
          method: 'POST',
          url: "/settings/license",
          data: {reporting_enabled: reporting_enabled,
            contract_id: contract_id,
            customer_token: customer_token},
        };
      // need to ignore placeholder tokens
      if (customer_token == "**********")
        delete request.data.customer_token;

      return $http(request);
    }

    //
    // validate the current settings
    function validateODPSettings(reporting_enabled, contract_id, customer_token) {
      var request = {
          method: 'POST',
          url: "/settings/license/validate",
          data: {reporting_enabled: reporting_enabled,
            contract_id: contract_id,
            customer_token: customer_token},
        };
      // need to ignore placeholder tokens
      if (customer_token == "**********")
        delete request.data.customer_token;

      return $http(request);
    }



  }
})();
