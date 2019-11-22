import angular from "/ui/web_modules/angular.js";

export default "mnInternalSettingsService";

angular
  .module("mnInternalSettingsService", [])
  .factory("mnInternalSettingsService", mnInternalSettingsFactory);

function mnInternalSettingsFactory($http) {
  var mnInternalSettingsService = {
    getState: getState,
    save: save
  };

  return mnInternalSettingsService;

  function save(data) {
    return $http({
      method: "POST",
      url: "/internalSettings",
      data: data
    });
  }

  function getState() {
    return $http({
      method: "GET",
      url: "/internalSettings"
    }).then(function (resp) {
      return resp.data;
    })
  }
}
