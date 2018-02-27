(function () {
  "use strict";

  angular
    .module("mnRedactionService", [
      "mnPoolDefault"
    ])
    .factory("mnRedactionService", mnRedactionFactory);

  function mnRedactionFactory($http, $q, mnPoolDefault) {
    var mnRedactionService = {
      getRedactionSettings: getRedactionSettings,
      postRedactionSettings: postRedactionSettings
    };

    return mnRedactionService;

    function getRedactionSettings() {
      return $http({
        method: 'GET',
        url: '/settings/redaction',
      }).then(function (resp) {
        return resp.data;
      });
    }

    function postRedactionSettings(data){
      var settings = _.clone(data);
      if (settings.state == 'disable') {
        settings.prefixes = settings.prefixes.filter(function (pref) {
          return !_.isEqual(pref, {delimiter: '', prefix: '', path: ''});
        });
      }
      if (!mnPoolDefault.export.compat.atLeast51 &&
          mnPoolDefault.export.compat.atLeast50) {
        (['delimiter', 'prefix', 'path']).forEach(function (key) {
          if (settings.prefixes[0] && settings.prefixes[0][key]) {
            settings[key] = settings.prefixes[0][key];
          }
        });
        delete settings.prefixes;
      }
      return $http({
        method: 'POST',
        url: '/settings/redaction',
        mnHttp: {
          isNotForm: mnPoolDefault.export.compat.atLeast51
        },
        data: settings,
      }).then(function (resp) {
        return resp.data;
      });
    }
  }
})();
