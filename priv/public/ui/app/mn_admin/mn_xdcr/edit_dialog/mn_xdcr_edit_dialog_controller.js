(function () {
  "use strict";

  angular.module('mnXDCR').controller('mnXDCREditDialogController', mnXDCREditDialogController);

  function mnXDCREditDialogController($scope, $uibModalInstance, mnPromiseHelper, mnXDCRService, currentSettings, globalSettings, id, source) {
    var vm = this;

    vm.settings = _.extend({fromBucket: source}, globalSettings.data, currentSettings.data);
    vm.settings.enableAdvancedFiltering = !!vm.settings.filterExpression;
    vm.settings.filterSkipRestream = "false";
    vm.createReplication = createReplication;

    function createReplication() {
      var settings = mnXDCRService.removeExcessSettings(vm.settings);
      if ($scope.pools.isEnterprise) {
        settings.filterExpression = vm.settings.filterExpression;
      }
      if (settings.filterExpression) {
        settings.filterSkipRestream = (vm.settings.filterSkipRestream === "true");
      }
      var promise = mnXDCRService.saveReplicationSettings(id, settings);
      mnPromiseHelper(vm, promise, $uibModalInstance)
        .showGlobalSpinner()
        .catchErrors()
        .closeOnSuccess()
        .broadcast("reloadTasksPoller")
        .showGlobalSuccess("Settings saved successfully!");
    };
  }
})();
