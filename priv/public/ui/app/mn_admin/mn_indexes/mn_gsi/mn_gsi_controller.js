(function () {
  "use strict";

  angular.module('mnGsi', [
    'mnHelper',
    'mnGsiService',
    'mnSortableTable',
    'mnPoll',
    'mnPoolDefault',
    'mnSpinner',
    'mnFilters',
    'mnSearch',
    'mnElementCrane',
    'ui.bootstrap',
    'mnPromiseHelper',
    'mnAlertsService',
    'mnStatisticsNewService'
  ]).controller('mnGsiController', mnGsiController);

  function mnGsiController($scope, mnGsiService, mnPoller) {
    var vm = this;
    vm.focusindexFilter = false;

    activate();

    function activate() {
      new mnPoller($scope, function () {
       return mnGsiService.getIndexesState();
      })
      .setInterval(10000)
      .subscribe("state", vm)
      .reloadOnScopeEvent("indexStatusURIChanged")
      .cycle();
    }
  }
})();
