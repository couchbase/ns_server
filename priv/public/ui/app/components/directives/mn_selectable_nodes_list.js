/*
Copyright 2018-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from 'angular';
import _ from 'lodash';

import mnFilters from '../mn_filters.js';
import mnSearch from './mn_search/mn_search_directive.js';
import template from "./mn_selectable_nodes_list.html";

export default 'mnSelectableNodesList';

angular
  .module("mnSelectableNodesList", [mnFilters, mnSearch])
  .directive("mnSelectableNodesList", mnSelectableNodesListDirective);

function mnSelectableNodesListDirective() {
  var mnSelectableNodesList = {
    restrict: "A",
    scope: {
      nodes: "=",
      mnIsNodeDisabled: "&?",
      mnGroups: "=?",
      mnSelectedNodesHolder: "="
    },
    template,
    controller: ["$scope", mnSelectableNodesListController],
    controllerAs: "mnThisCtl",
    bindToController: true
  };

  return mnSelectableNodesList;

  function mnSelectableNodesListController($scope) {
    var vm = this;

    vm.toggleAll = toggleAll;
    vm.findEnabled = findEnabled;
    vm.getGroupName = getGroupName;
    vm.areAllChecked = areAllChecked;

    function areAllChecked(bool) {
      return !!$scope.filteredNodes && !!$scope.filteredNodes.length && !findEnabled(bool);
    }

    function getGroupName(node) {
      return !!vm.mnGroups && vm.mnGroups[node.hostname].name;
    }

    function findEnabled(bool) {
      return !!_.find($scope.filteredNodes, function (node) {
        if (vm.mnIsNodeDisabled) {
          return !vm.mnIsNodeDisabled({node:node}) &&
            (!!vm.mnSelectedNodesHolder[node.otpNode] === bool);
        } else {
          return !!vm.mnSelectedNodesHolder[node.otpNode] === bool;
        }
      });
    }

    function setEnabled(bool) {
      $scope.filteredNodes.forEach(function (node) {
        if (vm.mnIsNodeDisabled) {
          if (!vm.mnIsNodeDisabled({node:node})) {
            vm.mnSelectedNodesHolder[node.otpNode] = bool;
          }
        } else {
          vm.mnSelectedNodesHolder[node.otpNode] = bool;
        }
      });
    }

    function toggleAll() {
      setEnabled(findEnabled(false));
    }
  }
}
