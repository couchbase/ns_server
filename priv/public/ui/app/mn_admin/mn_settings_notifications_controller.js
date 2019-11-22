import angular from "/ui/web_modules/angular.js";

import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnSettingsNotificationsService from "./mn_settings_notifications_service.js";
import mnSettingsClusterService from "./mn_settings_cluster_service.js"

export default "mnSettingsNotifications";

angular
  .module('mnSettingsNotifications', [
    mnPromiseHelper,
    mnSettingsNotificationsService,
    mnSettingsClusterService
  ])
  .controller('mnSettingsNotificationsController', mnSettingsNotificationsController);

function mnSettingsNotificationsController(mnPromiseHelper, mnSettingsNotificationsService, pools, mnSettingsClusterService) {
  var vm = this;

  mnSettingsClusterService.registerSubmitCallback(submit);
  vm.implementationVersion = pools.implementationVersion;

  activate();

  function activate() {
    mnPromiseHelper(vm, mnSettingsNotificationsService.maybeCheckUpdates())
      .applyToScope("updates");
  }

  function submit() {
    return mnPromiseHelper(vm, mnSettingsNotificationsService.saveSendStatsFlag(vm.updates.enabled))
      .catchGlobalErrors('An error occured, update notifications settings were not saved.')
      .getPromise();
  }
}
