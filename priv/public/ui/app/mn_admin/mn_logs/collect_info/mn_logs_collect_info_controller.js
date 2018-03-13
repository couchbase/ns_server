(function () {
  "use strict";

  angular
    .module('mnLogs')
    .controller('mnLogsCollectInfoController', mnLogsCollectInfoController);

  function mnLogsCollectInfoController($scope, mnHelper, mnPromiseHelper, mnPoolDefault, mnLogsCollectInfoService, mnPoller, $state, $uibModal, mnLogRedactionService, permissions, mnGroupsService) {
    var vm = this;
    vm.stopCollection = stopCollection;
    vm.isNodeDisabled = isNodeDisabled;
    vm.submit = submit;

    activate();

    vm.collect = {};
    vm.mnFilteredNodesHolder = {nodes: []};

    if (mnPoolDefault.latestValue().value.isEnterprise) {
      vm.collect.uploadHost = 's3.amazonaws.com/cb-customers';
    }

    function isNodeDisabled(node) {
      return node.status === 'unhealthy';
    }

    function activate() {
      if (mnPoolDefault.export.isGroupsAvailable && permissions.cluster.server_groups.read) {
        new mnPoller($scope, mnGroupsService.getGroupsByHostname)
          .subscribe("getGroupsByHostname", vm)
          .cycle();
      }
      new mnPoller($scope, mnLogsCollectInfoService.getState)
        .subscribe(function (state) {
          vm.loadingResult = false;
          vm.state = state;
        })
        .reloadOnScopeEvent("reloadCollectInfoPoller", vm, "loadingResult")
        .reloadOnScopeEvent("mnTasksDetailsChanged")
        .cycle();

      if (permissions.cluster.settings.read &&
          mnPoolDefault.export.compat.atLeast55 &&
          mnPoolDefault.export.isEnterprise) {
        mnLogRedactionService.get().then(function (value) {
          vm.collect.logRedactionLevel = value.logRedactionLevel;
        });
      }
    }

    function stopCollection() {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_logs/collect_info/mn_logs_collect_info_stop_dialog.html'
      }).result.then(function () {
        vm.disabledStopCollect = true;
        mnPromiseHelper(vm, mnLogsCollectInfoService.cancelLogsCollection())
          .getPromise()['finally'](function () {
            vm.disabledStopCollect = false;
          });
      });
    }
    function submit() {
      vm.collect.nodes = _.map(_.filter(vm.mnFilteredNodesHolder.nodes, {isSelected: true}), 'otpNode');
      mnPromiseHelper(vm, mnLogsCollectInfoService.startLogsCollection(vm.collect))
        .showSpinner()
        .catchErrors()
        .onSuccess(function () {
          vm.loadingResult = true;
          $state.go('app.admin.logs.collectInfo.result');
        });
    }
  }
})();
