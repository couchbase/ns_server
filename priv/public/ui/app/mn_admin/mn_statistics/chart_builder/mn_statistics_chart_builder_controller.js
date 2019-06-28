(function () {
  "use strict";

  angular
    .module("mnStatisticsNew")
    .controller("mnStatisticsNewChartBuilderController", mnStatisticsNewChartBuilderController)
    .filter("mnFormatStatsSections", mnFormatStatsSections);

  function mnFormatStatsSections() {
    return function (section) {
      section = section.substr(1);
      switch (section) {
      case "system": return "System";
      case "xdcr": return "XDCR";
      default: return section;
      }
    };
  }

  function mnStatisticsNewChartBuilderController($scope, mnPromiseHelper, mnBucketsStats, mnStatisticsNewService, chart, group, $uibModalInstance, mnStatisticsDescriptionService, $timeout, $state) {
    var vm = this;

    vm.create = create;

    vm.isEditing = !!chart

    vm.groups = mnStatisticsNewService.export.scenarios.selected.groups;
    vm.newChart = _.cloneDeep(chart) || {
      stats: {},
      size: "small",
      specificStat: "false",
      group: group && group.id.toString()
    };

    vm.bucket = $scope.rbac.bucketNames['.stats!read'][0];

    var initialGroup = vm.newChart.group;

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
    var selectedUnits = {};
    vm.selectedKVFilters = {};
    var selectedByNodeStats = {};
    var selectedStats = {};

    activate();

    function selectTab(name) {
      vm.selectedBlock = name;
    }

    function onSelectBucket() {
      activate();
      onSpecificChecked();
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


      vm.units = {};
      vm.breadcrumbs = {};
      vm.disableStats = false;

      _.forEach(vm.newChart.stats, activateStats);
    }

    function onStatChecked(desc, value, breadcrumb) {
      if (vm.units[desc.unit] === undefined) {
        vm.units[desc.unit] = 0;
      }

      if (value) {
        vm.units[desc.unit] += 1;
        vm.breadcrumbs[breadcrumb.join(" > ")] = true;
      } else {
        vm.units[desc.unit] -= 1;
        delete vm.breadcrumbs[breadcrumb.join(" > ")];
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
            _.forEach(chart.stats, activateStats);
          }
        })
        .showSpinner();

    }

    function create() {
      var chart = {
        size: vm.newChart.size,
        specificStat: vm.newChart.specificStat === "true",
        id: vm.newChart.id,
        group: vm.isEditing ? vm.newChart.group : group.id,
        stats: {}
      };
      var key;
      for (key in vm.newChart.stats) {
        if (vm.newChart.stats[key]) {
          chart.stats[key] = vm.newChart.stats[key];
        }
      }
      if (chart.id && (initialGroup !== vm.newChart.group)) {
        var fromGroup = _.find(vm.groups, {'id': initialGroup});
        var index = _.findIndex(fromGroup.charts, {'id': chart.id});
        var toGroup = _.find(vm.groups, {'id': vm.newChart.group});

        toGroup.charts.push(fromGroup.charts.splice(index, 1)[0]);
      }
      mnStatisticsNewService.addUpdateChart(
        chart,
        _.find(vm.groups, {'id': vm.newChart.group})
      ).then(function () {
        $uibModalInstance.close();
        vm.isEditing && $state.reload();
      });
    }

  }
})();
