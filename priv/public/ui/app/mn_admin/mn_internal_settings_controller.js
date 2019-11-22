import angular from "/ui/web_modules/angular.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnSpinner from "/ui/app/components/directives/mn_spinner.js";

import mnInternalSettingsService from "./mn_internal_settings_service.js";

export default "mnInternalSettings";

angular
  .module("mnInternalSettings", [
    mnPromiseHelper,
    mnSpinner,
    mnInternalSettingsService
  ])
  .controller("mnInternalSettingsController", mnInternalSettingsController);

function mnInternalSettingsController(mnInternalSettingsService, mnPromiseHelper, mnPoolDefault, $uibModalInstance) {
  var vm = this;

  vm.onSubmit = onSubmit;
  vm.mnPoolDefault = mnPoolDefault.latestValue();

  activate();

  function onSubmit() {
    if (vm.viewLoading) {
      return;
    }
    mnPromiseHelper(vm, mnInternalSettingsService.save(vm.state), $uibModalInstance)
      .showGlobalSpinner()
      .catchErrors()
      .closeOnSuccess()
      .reloadState()
      .showGlobalSuccess("Settings saved successfully!");
  }

  function activate() {
    mnPromiseHelper(vm, mnInternalSettingsService.getState())
      .showSpinner()
      .applyToScope("state");
  }
}
