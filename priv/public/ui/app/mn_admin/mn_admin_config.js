import mnAdminController from "./mn_admin_controller.js";

import angular from "/ui/web_modules/angular.js";
import _ from "/ui/web_modules/lodash.js";
import ngAnimate from "/ui/web_modules/angular-animate.js";

import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";
import uiRouter from "/ui/web_modules/@uirouter/angularjs.js";

import mnAlertsService from "/ui/app/components/mn_alerts.js";
import mnPoolDefault from "/ui/app/components/mn_pool_default.js";
import mnPoll from "/ui/app/components/mn_poll.js";
import mnFilters from "/ui/app/components/mn_filters.js";
import mnHelper from "/ui/app/components/mn_helper.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnMemoryQuotaService from "/ui/app/components/directives/mn_memory_quota/mn_memory_quota_service.js";
import mnLogsCollectInfoService from "/ui/app/mn_admin/mn_logs_collect_info_service.js";
import mnLaunchpad from "/ui/app/components/directives/mn_launchpad.js";
import mnPluggableUiRegistry from "/ui/app/components/mn_pluggable_ui_registry.js";

import mnAuthService from "/ui/app/mn_auth/mn_auth_service.js";
import mnClusterConfigurationService from "/ui/app/mn_wizard/mn_cluster_configuration/mn_cluster_configuration_service.js";
import mnPermissions from "/ui/app/components/mn_permissions.js";
import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";
import mnDragAndDrop from "/ui/app/components/directives/mn_drag_and_drop.js";
import mnTasksDetails from "/ui/app/components/mn_tasks_details.js";
import mnSessionService from "/ui/app/components/mn_session.js";
import mnLogsService from "./mn_logs_service.js";

import mnInternalSettings from "./mn_internal_settings_controller.js";
import mnLostConnection from "./mn_lost_connection_config.js";
import mnPoorMansAlerts from "./mn_poor_mans_alerts_controller.js"

import mnResetPasswordDialog from "./mn_reset_password_dialog_controller.js"
import mnResetPasswordDialogService from "./mn_reset_password_dialog_service.js";

import mnSettingsNotificationsService from "./mn_settings_notifications_service.js"
import uiSelect from "/ui/web_modules/ui-select.js";

import eventingUI from "/_p/ui/event/ui-current/eventing.js";

export default 'mnAdmin';

angular.module('mnAdmin', [
  eventingUI,

  ngAnimate,
  uiBootstrap,
  uiRouter,
  uiSelect,

  mnPoll,
  mnFilters,
  mnAlertsService,
  mnPoolDefault,
  mnLogsCollectInfoService,
  mnLogsService,

  mnTasksDetails,

  mnLaunchpad,
  mnPluggableUiRegistry,
  mnInternalSettings,
  mnLostConnection,
  mnPoorMansAlerts,
  mnPermissions,
  mnElementCrane,
  mnDragAndDrop,
  mnResetPasswordDialog,
  mnResetPasswordDialogService,
  mnSessionService,
  mnClusterConfigurationService,
  mnSettingsNotificationsService,
  mnMemoryQuotaService
]).config(mnAdminConfig)
  .controller('mnAdminController', mnAdminController);

//https://github.com/angular-ui/ui-select/issues/1560
angular.module('ui.select').run(function($animate) {
  var origEnabled = $animate.enabled
  $animate.enabled = function (elem) {
    if (arguments.length !== 1) {
      return origEnabled.apply($animate, arguments);
    } else if (origEnabled(elem)) {
      return (/enable-ng-animation/).test(elem.classNames);
    }
    return false
  }
});

function mnAdminConfig($stateProvider, $urlMatcherFactoryProvider, mnPluggableUiRegistryProvider) {

  function valToString(val) {
    return val != null ? val.toString() : val;
  }
  $urlMatcherFactoryProvider.type("string", {
    encode: valToString,
    decode: valToString,
    is: function (val) {
      return (/[^/]*/).test(val);
    }
  });

  mnPluggableUiRegistryProvider.registerConfig({
    name: 'Indexes',
    state: 'app.admin.gsi',
    includedByState: 'app.admin.gsi',
    plugIn: 'workbenchTab',
    index: 2,
    ngShow: "rbac.cluster.bucket['.'].n1ql.index.read"
  });

  $stateProvider
    .state('app.admin', {
      url: "?scenarioBucket&scenarioZoom&scenario",
      abstract: true,
      data: {
        requiresAuth: true
      },
      params: {
        scenarioBucket: {
          value: null
        },
        scenario: {
          value: null,
          dynamic: true
        },
        scenarioZoom: {
          value: "minute"
        }
      },
      resolve: {
        poolDefault: function (mnPoolDefault) {
          return mnPoolDefault.getFresh();
        },
        pools: function (mnPools) {
          return mnPools.get();
        },
        permissions: function (mnPermissions) {
          return mnPermissions.check();
        },
        whoami: function (mnAuthService) {
          return mnAuthService.whoami();
        }
      },
      views: {
        "": {
          controller: 'mnAdminController as adminCtl',
          templateUrl: 'app/mn_admin/mn_admin.html'
        },
        "lostConnection@app.admin": {
          templateUrl: 'app/mn_admin/mn_lost_connection.html',
          controller: 'mnLostConnectionController as lostConnCtl'
        }
      }
    })
    .state('app.admin.statistics_overview', {
      url: '/stats_overview?overviewHostname&overviewBucket&overviewZoom',
      views: {
        "main@app.admin": {
          controller: 'mnStatisticsOverviewController as statisticsOverviewCtl',
          templateUrl: 'app/mn_admin/mn_statistics_overview.html',
        }
      },
      data: {
        title: "Statistics Overview"
      }
    });

}
