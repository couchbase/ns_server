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
    'mnAlertsService'
  ]).controller('mnGsiController', mnGsiController);

  function mnGsiController($scope, mnGsiService, mnHelper, mnPoller, mnPoolDefault, $uibModal, mnPromiseHelper, mnAlertsService) {
    var vm = this;
    vm.generateIndexId = generateIndexId;
    vm.focusindexFilter = false;
    vm.hasQueryService = hasQueryService;
    vm.dropIndex = dropIndex;
    vm.editIndex = editIndex;

    activate();

    function generateIndexId(row) {
      return (row.id.toString() + (row.instId || "")) + (row.hosts ? row.hosts.join() : "");
    }

    function activate() {
      mnHelper.initializeDetailsHashObserver(vm, 'openedIndex', 'app.admin.indexes.gsi');

      new mnPoller($scope, function () {
       return mnGsiService.getIndexesState();
      })
      .setInterval(10000)
      .subscribe("state", vm)
      .reloadOnScopeEvent("indexStatusURIChanged")
      .cycle();
    }

    // we can show Edit / Delete buttons if there is a query service
    function hasQueryService() {
        return (mnPoolDefault.export.thisNode.services
                .indexOf('n1ql') != -1);
    }

    function dropIndex(row) {
      $uibModal.open({
        windowClass: "z-index-10001",
        backdrop: 'static',
        templateUrl: 'app/mn_admin/mn_indexes/mn_gsi/mn_gsi_drop_confirm_dialog.html'
      }).result.then(function () {
        row.awaytingRemoval = true;
        mnPromiseHelper(vm, mnGsiService.postDropIndex(row))
          .showGlobalSpinner()
          .catchErrors(function (resp) {
            if (!resp) {
              return;
            } else if (_.isString(resp)) {
              mnAlertsService.formatAndSetAlerts(resp.data, "error", 4000);
            } else if (resp.errors && resp.errors.length) {
              mnAlertsService.formatAndSetAlerts(_.map(resp.errors, "msg"), "error", 4000);
            }
            row.awaytingRemoval = false;
          })
          .showGlobalSuccess("Index dropped successfully!");
      });
    }

    // to edit an index, we create a 'CREATE' query to send to the query workbench
    function editIndex(row) {
        return (row.definition + '\nWITH {"nodes": ' + row.hosts.join(', ') + '}');
    }
  }
})();
