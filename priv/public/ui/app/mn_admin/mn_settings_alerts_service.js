import angular from "/ui/web_modules/angular.js";
import _ from "/ui/web_modules/lodash.js";

import mnHelper from "/ui/app/components/mn_helper.js";

export default 'mnSettingsAlertsService';

angular
  .module('mnSettingsAlertsService', [mnHelper])
  .factory('mnSettingsAlertsService', mnSettingsAlertsService);

function mnSettingsAlertsService($http, knownAlerts, mnHelper) {
  var mnSettingsAlertsService = {
    testMail: testMail,
    saveAlerts: saveAlerts,
    getAlerts: getAlerts
  };

  return mnSettingsAlertsService;

  function testMail(params) {
    params = _.clone(params);
    params.alerts = params.alerts.join(',');
    params.pop_up_alerts = settings.pop_up_alerts.join(',');
    return $http.post('/settings/alerts/testEmail', params);
  }
  function saveAlerts(settings, params) {
    settings = _.clone(settings);
    settings.alerts = settings.alerts.join(',');
    settings.pop_up_alerts = settings.pop_up_alerts.join(',');
    return $http.post('/settings/alerts', settings, {params: params});
  }
  function getAlerts() {
    return $http.get('/settings/alerts').then(function (resp) {
      var val = _.clone(resp.data);
      val.recipients = val.recipients.join('\n');
      val.knownAlerts = _.clone(knownAlerts);
      val.alerts = mnHelper.listToCheckboxes(val.alerts);
      if (val.pop_up_alerts == "undefined" || !val.pop_up_alerts) {
        val.popUpAlerts = {}
      } else {
        val.popUpAlerts = mnHelper.listToCheckboxes(val.pop_up_alerts);
      }

      return val;
    });
  }
}
