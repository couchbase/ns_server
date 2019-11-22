import angular from "/ui/web_modules/angular.js";

import mnHelper from "/ui/app/components/mn_helper.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";

import mnAutoCompactionForm from "/ui/app/components/directives/mn_auto_compaction_form/mn_auto_compaction_form.js";
import mnSettingsAutoCompactionService from "./mn_settings_auto_compaction_service.js";

export default 'mnSettingsAutoCompaction';

angular
  .module('mnSettingsAutoCompaction', [
    mnHelper,
    mnPromiseHelper,
    mnAutoCompactionForm,
    mnSettingsAutoCompactionService
  ])
  .controller('mnSettingsAutoCompactionController', mnSettingsAutoCompactionController);

function mnSettingsAutoCompactionController($scope, mnHelper, mnPromiseHelper, mnSettingsAutoCompactionService) {
  var vm = this;

  vm.reloadState = mnHelper.reloadState;
  vm.submit = submit;

  activate();

  function activate() {
    mnPromiseHelper(vm, mnSettingsAutoCompactionService.getAutoCompaction())
      .applyToScope("autoCompactionSettings")
      .onSuccess(function () {
        $scope.$watch('settingsAutoCompactionCtl.autoCompactionSettings', watchOnAutoCompactionSettings, true);
      });
  }
  function watchOnAutoCompactionSettings(autoCompactionSettings) {
    if (!$scope.rbac.cluster.settings.write) {
      return;
    }
    mnPromiseHelper(vm, mnSettingsAutoCompactionService
                    .saveAutoCompaction(autoCompactionSettings, {just_validate: 1}))
      .catchErrors();
  }
  function submit() {
    if (vm.viewLoading) {
      return;
    }
    delete vm.errors;
    mnPromiseHelper(vm, mnSettingsAutoCompactionService.saveAutoCompaction(vm.autoCompactionSettings))
      .showGlobalSpinner()
      .reloadState()
      .catchErrors()
      .showGlobalSuccess("Settings saved successfully!");
  }
}
