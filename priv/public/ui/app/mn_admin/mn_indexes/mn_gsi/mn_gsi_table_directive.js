(function () {
  "use strict";

  angular
    .module('mnGsi')
    .directive('mnGsiTable', mnGsiTableDirective);

  function mnGsiTableDirective(mnHelper) {
    var mnGsiTable = {
      restrict: 'EA',
      scope: {
        list: "=",
        hideColumn: "@",
        filterField: "=",
        rbac: "=",
        pools: "=",
        nodeName: "@?"
      },
      controller: mnGsiTableController,
      controllerAs: "mnGsiTableCtl",
      bindToController: true,
      templateUrl: 'app/mn_admin/mn_indexes/mn_gsi/mn_gsi_table_directive.html'
    };

    return mnGsiTable;

    function mnGsiTableController() {
      var vm = this;
      vm.generateIndexId = generateIndexId;
      vm.getStatusClass = getStatusClass;

      mnHelper.initializeDetailsHashObserver(vm, 'openedIndex', 'app.admin.gsi');


      function generateIndexId(row, partitionHost) {
        return (row.id.toString() + (row.instId || "")) +
          (row.hosts ? row.hosts.join() : "") +
          (vm.nodeName || "");
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

    }
  }
})();
