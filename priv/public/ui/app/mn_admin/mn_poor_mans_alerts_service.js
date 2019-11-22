import angular from "/ui/web_modules/angular.js";
import _ from "/ui/web_modules/lodash.js";

import uiRouter from "/ui/web_modules/@uirouter/angularjs.js";
import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";
import mnHelper from "/ui/app/components/mn_helper.js";

export default "mnPoorMansAlertsService";

angular
  .module("mnPoorMansAlertsService", [
    uiRouter,
    uiBootstrap,
    mnHelper
  ])
  .factory("mnPoorMansAlertsService", mnPoorMansAlertsFactory);

function mnPoorMansAlertsFactory($http, $state, $uibModal, mnHelper, $timeout) {
  var alerts = [];
  var modal;
  var modalDeferId;

  var mnPoorMansAlerts = {
    maybeShowAlerts: maybeShowAlerts,
    postAlertsSilenceURL: postAlertsSilenceURL
  };

  return mnPoorMansAlerts;

  function postAlertsSilenceURL(alertsSilenceURL) {
    return $http({
      method: "POST",
      url: alertsSilenceURL,
      timeout: 5000,
      data: ''
    });
  }

  function maybeShowAlerts(poolDefault) {
    if ($state.params.disablePoorMansAlerts) {
      return;
    }
    alerts = poolDefault.alerts;
    if (!alerts.length) {
      return;
    }
    if (modalDeferId) {
      $timeout.cancel(modalDeferId);
    }
    if (modal) {
      modal.dismiss();
      modal = null;
      modalDeferId = $timeout(function () { //we need this in order to allow uibModal close backdrop
        modal = doShowAlerts(poolDefault.alertsSilenceURL, alerts);
      }, 0);
    } else {
      modal = doShowAlerts(poolDefault.alertsSilenceURL, alerts);
    }
  }

  function doShowAlerts(alertsSilenceURL, alerts) {
    return $uibModal.open({
      templateUrl: "app/mn_admin/mn_poor_mans_alerts.html",
      controller: "mnPoorMansAlertsController as poorMansCtl",
      resolve: {
        alertsSilenceURL: mnHelper.wrapInFunction(alertsSilenceURL),
        alerts: mnHelper.wrapInFunction(_.clone(alerts, true))
      }
    });
  }
}
