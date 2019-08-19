(function () {
  "use strict";

  angular
    .module("mnStatisticsNew")
    .controller("mnStatisticsNewChartBuilderController", mnStatisticsNewChartBuilderController)
    .filter("mnFormatStatsSections", mnFormatStatsSections);

  function mnFormatStatsSections() {
    return function (section) {
      if (section.includes("@")) {
        section = section.substr(1);
      }

      if (section.includes("-")) {
        section = section.substr(0, section.length-1);
      }

      switch (section) {
      case "system": return "System";
      case "xdcr": return "XDCR";
      default: return section;
      }
    };
  }

  function mnStatisticsNewChartBuilderController($scope, mnPromiseHelper, mnBucketsStats, mnStatisticsNewService, mnUserRolesService, chart, group, scenario, $uibModalInstance, mnStatisticsDescriptionService, $state, mnFormatStatsSectionsFilter, mnFormatServicesFilter, mnStoreService) {
    var vm = this;
    vm.isEditing = !!chart;
    vm.create = create;

    if (vm.isEditing) {
      vm.newChart = _.cloneDeep(chart);
      vm.selectedGroup = group.id;
      vm.groups = scenario.groups.map(function (id) {
        return mnStoreService.store("groups").get(id);
      });
    } else {
      vm.newChart = {
        stats: {},
        size: "small",
        specificStat: "false"
      };
    }

    vm.bucket = $scope.rbac.bucketNames['.stats!read'][0];

    if (vm.newChart.specificStat) {
      vm.newChart.specificStat = "true";
    } else {
      vm.newChart.specificStat = "false";
    }

    vm.units = {};
    vm.breadcrumbs = {};
    vm.showInPopup = false;
    vm.onStatChecked = onStatChecked;
    vm.onSpecificChecked = onSpecificChecked;
    vm.maybeDisableField = maybeDisableField;
    vm.filterStats = filterStats;
    vm.selectTab = selectTab;
    vm.onSelectBucket = onSelectBucket;
    vm.statsDesc = mnStatisticsDescriptionService.stats;
    vm.kvGroups = mnStatisticsDescriptionService.kvGroups;
    vm.orderPills = orderPills;
    vm.getSelectedStats = getSelectedStats;
    vm.getSelectedStatsLength = getSelectedStatsLength;
    vm.formatGroupLabel = formatGroupLabel;
    var selectedUnits = {};
    vm.selectedKVFilters = {};
    var selectedByNodeStats = {};
    var selectedStats = {};



    activate();

    function formatGroupLabel(service) {
      switch (service) {
      case "@index": return "Indexes";
      case "@xdcr": return "Replications";
      case "@kv": return "Views";
      default: return "Items";
      }
    }

    function orderPills(statsDirectoryBlocks) {
      var order = ["@system", "@kv", "@index", "@query", "@fts", "@cbas", "@eventing", "@xdcr"];
      return Object.keys(statsDirectoryBlocks || {}).sort(function (a, b) {
        return order.indexOf(a) - order.indexOf(b);
      });
    }

    function selectTab(name) {
      delete vm.groupItem;
      vm.selectedBlock = name;
    }

    function getSelectedStatsLength() {
      return Object.keys(getSelectedStats()).length;
    }

    function getSelectedStats() {
      return Object
        .keys(vm.newChart.stats)
        .reduce(function (acc, key) {
          if (vm.newChart.stats[key]) {
            acc[key] = vm.newChart.stats[key];
          }
          return acc;
        }, {});
    }

    function reActivateStats() {
      vm.units = {};
      vm.breadcrumbs = {};
      vm.disableStats = false;

      _.forEach(getSelectedStats(), activateStats);
    }

    function onSelectBucket() {
      activate();
      reActivateStats();
    }

    function filterStats(section) {
      return !section.includes("-");
    }

    function maybeDisableField(stat, name) {
      return ((vm.newChart.specificStat == "false") &&
              vm.disableStats && !vm.units[stat.unit]) ||
        (vm.newChart.specificStat == "true" &&
         vm.disableStats &&
         !vm.newChart.stats[name]);
    }

    function onSpecificChecked() {
      if (vm.newChart.specificStat == "true") {
        selectedStats = vm.newChart.stats;
        vm.newChart.stats = selectedByNodeStats;
      } else {
        selectedByNodeStats = vm.newChart.stats;
        vm.newChart.stats = selectedStats;
      }

      reActivateStats();
    }

    function onStatChecked(desc, value, breadcrumb) {
      if (vm.units[desc.unit] === undefined) {
        vm.units[desc.unit] = 0;
      }

      if (value) {
        vm.units[desc.unit] += 1;
        vm.breadcrumbs[breadcrumb
                       .map(mnFormatStatsSectionsFilter)
                       .map(mnFormatServicesFilter)
                       .join(" > ")] = true;
      } else {
        vm.units[desc.unit] -= 1;
        delete vm.breadcrumbs[breadcrumb
                              .map(mnFormatStatsSectionsFilter)
                              .map(mnFormatServicesFilter)
                              .join(" > ")];
      }

      var selectedUnitsCount =
          Object.keys(vm.units).reduce(function (acc, key) {
            if (vm.units[key] > 0) {
              acc += 1
            }
            return acc;
          }, 0);

      if (vm.newChart.specificStat !== "false") {
        vm.disableStats = selectedUnitsCount >= 1;
      } else {
        vm.disableStats = selectedUnitsCount >= 2;
      }
    }

    function activateStats(descPath, statName) {
      var breadcrumb = [descPath.split(".")[0]];
      var splited = statName.split("/");
      var desc = mnStatisticsNewService.readByPath(descPath, statName);

      if (splited.length > 2) {
        splited.pop();
        breadcrumb.push(splited.join("/"));
      }

      breadcrumb.push(desc.title);

      onStatChecked(desc, true, breadcrumb);
    }

    function activate() {
      mnPromiseHelper(vm, mnStatisticsNewService.doGetStats({
        bucket: vm.bucket,
        node: "all",
        zoom: "minute"
      }))
        .applyToScope(function (rv) {
          // var stats = rv.data.stats;
          var stats = Object.keys(rv.data.stats).reduce(function (acc, key) {
            acc[key] = Object.keys(rv.data.stats[key]).reduce(function (acc, statName) {
              var splited = statName.split("/");
              if (splited.length > 2) {
                var actualStatName = splited.pop();
                var groupName = splited.join("/");
                if (!acc["@items"]) {
                  acc["@items"] = {};
                }
                if (!acc["@items"][groupName]) {
                  acc["@items"][groupName] = {};
                }
                acc["@items"][groupName][actualStatName] = rv.data.stats[key][statName];
              } else {
                acc[statName] = rv.data.stats[key][statName];
              }
              return acc;
            }, {});
            return acc;
          }, {});
          stats["@kv"] = rv.data.stats["@kv"] || {};
          stats["@xdcr"] = rv.data.stats["@xdcr"] || {};
          vm.statsDirectoryBlocks = stats;
          vm.selectedBlock = vm.selectedBlock || "@system";

          if (chart) {
            _.forEach(getSelectedStats(), activateStats);
          }
        })
        .showSpinner();
    }

    function create() {
      var chart = {
        size: vm.newChart.size,
        specificStat: vm.newChart.specificStat === "true",
        id: vm.newChart.id,
        stats: getSelectedStats()
      };
      var toGroup = mnStoreService.store("groups").get(vm.selectedGroup || group.id);
      var fromGroup;
      if (vm.isEditing) {
        if (group.id !== vm.selectedGroup) {
          fromGroup = mnStoreService.store("groups").get(group.id);
          fromGroup.charts.splice(fromGroup.charts.indexOf(chart.id), 1);
          toGroup.charts.push(chart.id);
        }
        mnStoreService.store("charts").put(chart);
      } else {
        toGroup.charts.push(mnStoreService.store("charts").add(chart).id);
      }
      $uibModalInstance.close();
    }

  }
})();
