(function () {
  "use strict"

  angular
    .module('mnStatisticsChart', [
      "mnStatisticsNewService",
      "mnStatisticsDescriptionService",
      "ui.bootstrap",
      "mnPoll",
      "mnFilters",
      "mnHelper"
    ])
    .directive("mnStatisticsChart", mnStatisticsNewChartDirective);

  function mnStatisticsNewChartDirective(mnStatisticsNewService, mnStatisticsDescriptionService, $uibModal, $state, mnPoller, mnPrepareQuantityFilter, mnTruncateTo3DigitsFilter, $rootScope, mnHelper) {
    return {
      restrict: 'A',
      templateUrl: 'app/mn_admin/mn_statistics/chart_directive/mn_statistics_chart_directive.html',
      scope: {
        config: "=",
        nodes: "=",
        rbac: "=",
        isModal: "=?"
      },
      controller: controller
    };

    function controller($scope) {
      var breakInterval;
      var poller;
      var units;

      $scope.editChart = editChart;
      $scope.selectedBucket = $scope.config.bucket;
      $scope.deleteChart = deleteChart;

      if (!_.isEmpty($scope.config.stats)) {
        units = mnStatisticsNewService.getStatsUnits($scope.config.stats);
        $scope.title = mnStatisticsNewService.getStatsTitle($scope.config.stats);
        activate();
      }

      function deleteChart(config) {
        $uibModal.open({
          templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder_delete.html',
          scope: $scope
        }).result.then(function () {
          var group = _.find(mnStatisticsNewService.export.scenarios.selected.groups,
                             {'id': config.group});

          var index = _.findIndex(group.charts, {'id': config.id});

          group.charts.splice(index, 1);

          mnStatisticsNewService.saveScenarios();
        });
      }

      function editChart(config) {
        $uibModal.open({
          templateUrl: 'app/mn_admin/mn_statistics/chart_builder/mn_statistics_chart_builder.html',
          controller: 'mnStatisticsNewChartBuilderController as chartBuilderCtl',
          resolve: {
            chart: mnHelper.wrapInFunction(config),
            group: mnHelper.wrapInFunction()
          }
        }).result.then(function () {
          $state.reload();
        });
      }

      function activate() {
        initConfig();
        subscribeToMultiChartData();
      }

      function subscribeToMultiChartData() {
        $scope.$on("$destroy", function () {
          mnStatisticsNewService.unsubscribeChartStats($scope.config, $scope, $state.params.scenarioBucket);
        });
        mnStatisticsNewService.subscribeToChartStats($scope.config, $scope, $state.params.scenarioBucket);
        $scope.$watch("mnChartStats", onMultiChartDataUpdate);
      }

      function initConfig() {
        var options = {
          chart: {
            type: 'multiChart',
            height: Number($scope.config.height),
            margin : {
              top: 32,
              right: 40,
              bottom: 40,
              left: 40
            },
            legendPosition: "bottom",
            legendLeftAxisHint: " (left axis)",
            legendRightAxisHint: " (right axis)",
            interactiveLayer: {
              tooltip: {
                valueFormatter: function (d, s, c, g, f, a) {
                  return formatValue(d,c.yAxis.axisLabel());
                }
              }
            },
            defined: function (item, index) {
              if (!$scope.chartData) {
                return
              }
              var prev = $scope.chartData[item.series].values[index - 1];
              // console.log(item[0],  (prev && prev[0] + breakInterval), prev && prev[0])
              if (prev) {
                if (item[0] > (prev[0] + breakInterval)) {
                  return false;
                }
              }
              return true;
            },
            x: function (d) {
              return (d && d[0]) || 0;
            },
            y: function (d) {
              return (d && d[1]) || 0;
            },
            interpolate: "linear",
            showLegend: !!$scope.isModal,
            duration: 0,
            useInteractiveGuideline: true,
            xScale: d3.time.scale(),
            xAxis: {
              axisLabel: "",
              showMaxMin: false,
              tickFormat: function (d) {
                return mnStatisticsNewService.tickMultiFormat(new Date(d));
              }
            },
            yAxis: {
              axisLabel : "",
              showMaxMin: false
            },
            callback: function (chart) {
              chart && chart.interactiveLayer.dispatch.on("elementClick", function () {
                if ($scope.isModal) {
                  return;
                }
                if (Object.keys(units).length === 1) {
                  $uibModal.open({
                    templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_chart_focus_dialog.html',
                    controller: 'mnStatisticsChartFocusDialogController as chartFocusDialogCtl',
                    windowTopClass: "chart-overlay",
                    resolve: {
                      chartConfig: mnHelper.wrapInFunction($scope.config),
                      chartNodes: mnHelper.wrapInFunction($scope.nodes)
                    }
                  });
                } else {
                  var scope = $rootScope.$new();
                  scope.config = $scope.config;
                  scope.nodes = $scope.nodes;
                  $uibModal.open({
                    templateUrl: 'app/mn_admin/mn_statistics/mn_statistics_chart_dialog.html',
                    scope: scope,
                    windowTopClass: "chart-overlay"
                  });
                }
              });
            }
          }
        };

        function formatValue(d, unit) {
          switch (unit) {
          case "bytes":
            var val = mnPrepareQuantityFilter(d, 1024);
            return [mnTruncateTo3DigitsFilter(d/val[0]), val[1]].join('');
          case "percent":
            return  mnTruncateTo3DigitsFilter(d) + "%";
          default: return d;
          }
        }

        var index = 0;
        _.forEach(units, function (val, unit) {
          index ++;
          units[unit] = index;
          options.chart["yAxis" + index] = {};
          options.chart["yAxis" + index].axisLabel = unit; //hack that is involved in order to show current stats value in tooltip correctly
          options.chart["yAxis" + index].tickFormat = function (d) {
            return formatValue(d, unit);
          }
        });

        //options.chart.yAxis.showMaxMin = false;

        $scope.options = options;
      }

      function onMultiChartDataUpdate(stats) {
        if (!stats) {
          return
        }

        var chartData = [];
        if ($scope.config.specificStat) {
          angular.forEach($scope.config.stats, function (descPath, statName) {
            var desc = mnStatisticsNewService
                .readByPath(mnStatisticsDescriptionService.stats, descPath);
            angular.forEach(stats.data.samples, function (nodeStat, nodeName) {
              chartData.push({
                type: 'line',
                unit: desc.unit,
                yAxis: units[desc.unit],
                key: nodeName,
                values: _.zip(nodeStat.timestamps, nodeStat)
              });
            });
          });

        } else {
          angular.forEach($scope.config.stats, function (descPath, name) {
            if (!descPath) {
              return;
            }
            var desc = mnStatisticsNewService
                .readByPath(mnStatisticsDescriptionService.stats, descPath);
            chartData.push({
              type: 'line',
              unit: desc.unit,
              yAxis: units[desc.unit],
              key: desc.title,
                values: _.zip(stats.data.samples[name] ?
                              stats.data.samples[name].timestamps : [],
                              stats.data.samples[name])
            });
          });
        }
        $scope.chartApi.updateWithData(chartData);
      }
    }
  }
})();
