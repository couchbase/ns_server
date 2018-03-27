(function () {
  "use strict";

  angular.module('mnGsi', [
    'mnHelper',
    'mnGsiService',
    'mnSortableTable',
    'mnPoll',
    'mnSpinner',
    'mnFilters',
    'mnSearch',
    'mnElementCrane',
    'ui.bootstrap',
    'mnPromiseHelper',
    'mnAlertsService',
    'mnServersService'
  ]).controller('mnGsiController', mnGsiController);

  function mnGsiController($scope, $rootScope, mnGsiService, mnHelper, mnPoller, $uibModal, mnPromiseHelper, mnServersService, mnAlertsService) {
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

      new mnPoller($scope, function () {
        return mnServersService.getNodes();
      })
        .subscribe("nodes", vm)
        .reloadOnScopeEvent(["mnPoolDefaultChanged", "reloadNodes"])
        .cycle();
    }

    function hasQueryService() {
      return !!vm.nodes && !!_.find(vm.nodes.active, function (server) {
        return _.indexOf(server.services, "n1ql") > -1;
      });
    }

    function dropIndex(row) {
      var scope = $rootScope.$new();
      scope.partitioned = row.partitioned;
      $uibModal.open({
        windowClass: "z-index-10001",
        backdrop: 'static',
        templateUrl: 'app/mn_admin/mn_indexes/mn_gsi/mn_gsi_drop_confirm_dialog.html',
        scope: scope
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
