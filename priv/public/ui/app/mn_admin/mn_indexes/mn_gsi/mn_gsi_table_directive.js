(function () {
  "use strict";

  angular
    .module('mnGsi')
    .directive('mnGsiTable', mnGsiTableDirective);

  function mnGsiTableDirective($rootScope, mnGsiService, mnPoolDefault, $uibModal, mnPromiseHelper, mnAlertsService, mnHelper) {
    var mnGsiTable = {
      restrict: 'EA',
      scope: {
        list: "=",
        hideColumn: "@",
        filterField: "=",
        rbac: "=",
        pools: "="
      },
      controller: mnGsiTableController,
      controllerAs: "mnGsiTableCtl",
      bindToController: true,
      templateUrl: 'app/mn_admin/mn_indexes/mn_gsi/mn_gsi_table_directive.html'
    };

    return mnGsiTable;

    function mnGsiTableController($scope) {
      var vm = this;
      vm.generateIndexId = generateIndexId;
      vm.hasQueryService = hasQueryService;
      vm.dropIndex = dropIndex;
      vm.getStatusClass = getStatusClass;

      mnHelper.initializeDetailsHashObserver(vm, 'openedIndex', 'app.admin.gsi');


      function generateIndexId(row) {
        return (row.id.toString() + (row.instId || "")) + (row.hosts ? row.hosts.join() : "");
      }

      // we can show Edit / Delete buttons if there is a query service
      function hasQueryService() {
        return (mnPoolDefault.export.thisNode.services
                .indexOf('n1ql') != -1);
      }

      function getStatusClass(row) {
        row = row || {};
        switch (row.status) {
        case 'Ready': return 'dynamic_healthy';
        case 'Not Available':
        case 'Error': return 'dynamic_unhealthy';
        default: return 'dynamic_warmup';
        }
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
          row.awaitingRemoval = true;
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
              row.awaitingRemoval = false;
            })
            .showGlobalSuccess("Index dropped successfully!");
        });
      }

    }
  }
})();
