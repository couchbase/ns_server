/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from "angular";
import _ from "lodash";

import mnPoolDefault from "../components/mn_pool_default.js";
import mnPromiseHelper from "../components/mn_promise_helper.js";

import mnSettingsClusterService from "./mn_settings_cluster_service.js";
import mnSettingsAutoFailoverService from "./mn_settings_auto_failover_service.js";

export default 'mnSettingsAutoFailover';

angular
  .module('mnSettingsAutoFailover', [
    mnPromiseHelper,
    mnPoolDefault,
    mnSettingsClusterService,
    mnSettingsAutoFailoverService
  ])
  .controller('mnSettingsAutoFailoverController', ["$scope", "$q", "mnPromiseHelper", "mnSettingsAutoFailoverService", "mnPoolDefault", "mnSettingsClusterService", mnSettingsAutoFailoverController]);

function mnSettingsAutoFailoverController($scope, $q, mnPromiseHelper, mnSettingsAutoFailoverService, mnPoolDefault, mnSettingsClusterService) {
  var vm = this;

  mnSettingsClusterService.registerSubmitCallback(submit);
  mnSettingsClusterService.registerInitChecker(() => (!!vm.autoFailoverSettings &&
                                                      !!vm.reprovisionSettings));

  activate();

  function getAutoFailoverSettings() {
    if (!vm.autoFailoverSettings) {
      return;
    }
    var settings = {
      enabled: vm.autoFailoverSettings.enabled,
      timeout: vm.autoFailoverSettings.timeout
    };

    if (mnPoolDefault.export.isEnterprise) {
        if (mnPoolDefault.export.compat.atLeast55) {
            settings.failoverOnDataDiskIssues = vm.autoFailoverSettings.failoverOnDataDiskIssues;
            settings.maxCount = vm.autoFailoverSettings.maxCount;
        }

        if (mnPoolDefault.export.compat.atLeast72) {
            settings.failoverPreserveDurabilityMajority = vm.autoFailoverSettings.failoverPreserveDurabilityMajority;
        }

        if (mnPoolDefault.export.compat.atLeast79) {
            settings.allowFailoverEphemeralNoReplicas =
                vm.autoFailoverSettings.allowFailoverEphemeralNoReplicas;
            settings.failoverOnDataDiskNonResponsiveness = vm.autoFailoverSettings.failoverOnDataDiskNonResponsiveness;
        }
    }

    return settings;
  }

  function getReprovisionSettings() {
    return {
      enabled: vm.reprovisionSettings.enabled,
      maxNodes: vm.reprovisionSettings.max_nodes
    };
  }

  function watchOnSettings(method, dataFunc) {
    return function () {
      if (!$scope.rbac.cluster.settings.write) {
        return;
      }

      var values = dataFunc();
      // autofailover timeout doesn't pass minimum of 5 seconds validation (input min="5")
      if (method === "saveAutoFailoverSettings" && values.timeout === undefined) {
        // show custom error and don't send validation to the server
        var err = { "timeout" : "The value must be in range from 5 to 3600" };
        vm[method + "Errors"] = err;
        $scope.settingsClusterCtl[method + "Errors"] = err;
        return;
      }

      mnPromiseHelper(vm, mnSettingsAutoFailoverService[method](values, {just_validate: 1}))
        .catchErrors(function (rv) {
          vm[method + "Errors"] = rv;
          $scope.settingsClusterCtl[method + "Errors"] = rv;
        });
    }
  }

  function activate() {
    mnPromiseHelper(vm, mnSettingsAutoFailoverService.getAutoReprovisionSettings())
      .applyToScope(function (resp) {
        vm.reprovisionSettings = resp.data;

        $scope.$watch(
          'settingsAutoFailoverCtl.reprovisionSettings',
          _.debounce(watchOnSettings("postAutoReprovisionSettings", getReprovisionSettings),
                     500, {leading: true}), true);
      });

    mnPromiseHelper(vm,
                    mnSettingsAutoFailoverService.getAutoFailoverSettings())
      .applyToScope(function (resp) {
        vm.autoFailoverSettings = resp;

        $scope.$watch(
          'settingsAutoFailoverCtl.autoFailoverSettings',
          _.debounce(watchOnSettings("saveAutoFailoverSettings", getAutoFailoverSettings),
                     500, {leading: true}), true);
      });
  }

  function submit() {
    var queries = [
      mnPromiseHelper(vm, mnSettingsAutoFailoverService.saveAutoFailoverSettings(getAutoFailoverSettings()))
        .catchErrors(function (resp) {
          vm.saveAutoFailoverSettingsErrors = resp && {timeout: resp};
        })
        .getPromise(),

      mnPromiseHelper(vm, mnSettingsAutoFailoverService.postAutoReprovisionSettings(getReprovisionSettings()))
        .catchErrors(function (resp) {
          vm.postAutoReprovisionSettingsErrors = resp && {maxNodes: resp};
        })
        .getPromise()
    ];

    return $q.all(queries);
  }
}
