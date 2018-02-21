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
    'mnElementCrane'
  ]).controller('mnGsiController', mnGsiController);

  function mnGsiController($scope, mnGsiService, mnHelper, mnPoller, mnPoolDefault) {
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
        return (mnPoolDefault.latestValue().value.thisNode.services
                .indexOf('n1ql') != -1);
    }

    // to drop an index, we create a 'DROP' query to send to the query workbench
    function dropIndex(row) {
        //console.log("dropping row: " + JSON.stringify(row));
        return('DROP INDEX `' + row.bucket + '`.`' + row.index + '`');
    }

    // to edit an index, we create a 'CREATE' query to send to the query workbench
    function editIndex(row) {
        //console.log("Editing row: " + JSON.stringify(row));
        return(row.definition + '\nWITH {"nodes": ' + row.hosts.join(', ') + '}');
    }
  }
})();
