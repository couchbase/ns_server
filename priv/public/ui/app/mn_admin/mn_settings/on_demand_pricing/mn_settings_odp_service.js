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
      }).then(function (resp) {
        return resp.data;
      });
    }
    function saveODPSettings(settings) {
      return $http({
        method: 'POST',
        url: "/settings/license",
        data: packData(settings)
      });
    }
    function validateODPSettings(settings) {
      return $http({
        method: 'POST',
        url: "/settings/license/validate",
        data: packData(settings)
      });
    }
    //
    // Parameters to save:
    // - reporting_enabled
    // - contract_id
    // - customer_token
    //
    function packData(settings) {
      var rv = {};
      var fields = ["reporting_enabled"];
      // need to ignore placeholder tokens
      if (settings.reporting_enabled) {
        fields.push("contract_id");
        if (settings.customer_token !== "**********") {
          fields.push("customer_token");
        }
      }
      fields.forEach(function (field) {
        rv[field] = settings[field];
      });
      return rv;
    }

  }
})();
