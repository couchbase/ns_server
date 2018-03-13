(function () {
  "use strict";

  angular
    .module("mnSelectableNodesList", [
      "mnFilters",
      "mnSearch"
    ])
    .directive("mnSelectableNodesList", mnSelectableNodesListDirective);

  function mnSelectableNodesListDirective() {
    var mnSelectableNodesList = {
      restrict: "A",
      scope: {
        nodes: "=",
        mnIsNodeDisabled: "&?",
        mnGroups: "=?",
        mnFilteredNodesHolder: "="
      },
      templateUrl: "app/components/directives/mn_selectable_nodes_list.html",
      controller: mnSelectableNodesListController,
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
        return !!vm.mnFilteredNodesHolder.nodes.length && !findEnabled(bool);
      }

      function getGroupName(node) {
        return !!vm.mnGroups && vm.mnGroups[node.hostname].name;
      }

      function findEnabled(bool) {
        return !!_.find(vm.mnFilteredNodesHolder.nodes, function (node) {
          if (vm.mnIsNodeDisabled) {
            return !vm.mnIsNodeDisabled({node:node}) && !!node.isSelected === bool;
          } else {
            return !!node.isSelected === bool;
          }
        });
      }

      function setEnabled(bool) {
        vm.mnFilteredNodesHolder.nodes.forEach(function (node) {
          if (vm.mnIsNodeDisabled) {
            if (!vm.mnIsNodeDisabled({node:node})) {
              node.isSelected = bool;
            }
          } else {
            node.isSelected = bool;
          }
        });
      }

      function toggleAll() {
        setEnabled(findEnabled(false));
      }
    }
  }
})();
