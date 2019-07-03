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

  function mnStatisticsNewChartDirective(mnStatisticsNewService, mnStatisticsDescriptionService, $uibModal, $state, mnPrepareQuantityFilter, mnTruncateTo3DigitsFilter, $rootScope, mnHelper, $timeout) {
    return {
      restrict: 'AE',
      templateUrl: 'app/mn_admin/mn_statistics/chart_directive/mn_statistics_chart_directive.html',
      scope: {
        config: "=",
        getNvd3Options: "&?",
        bucket: "@",
        zoom: "@"
      },
      controller: controller
    };

    function controller($scope) {
      var units;

      if (!_.isEmpty($scope.config.stats)) {
        units = mnStatisticsNewService.getStatsUnits($scope.config.stats);
        $scope.title = mnStatisticsNewService.getStatsTitle($scope.config.stats);
        $scope.desc = mnStatisticsNewService.getStatsDesc($scope.config.stats);
        activate();
      }

      function defaultValueFormatter(d, s, c, g, f, a) {
        return formatValue(d, c.yAxis.axisLabel());
      }

      function activate() {
        initConfig();
        subscribeToMultiChartData();
      }

      function subscribeToMultiChartData() {
        mnStatisticsNewService.subscribeUIStatsPoller({
          bucket: $scope.bucket,
          node: $scope.config.node || "all",
          stats: $scope.config.stats,
          zoom: $scope.zoom,
          specificStat: $scope.config.specificStat
        }, $scope);

        $scope.$watch("mnUIStats", onMultiChartDataUpdate);
      }

      function initConfig() {
        var options = {
          chart: {
            type: 'multiChart',
            margin : {top: 32, right: 40, bottom: 40, left: 40},
            legendPosition: "bottom",
            legendLeftAxisHint: " (left axis)",
            legendRightAxisHint: " (right axis)",
            interactiveLayer: {tooltip: {valueFormatter: defaultValueFormatter}},
            x: function (d, b) {
              return (d && d[0]) || 0;
            },
            y: function (d) {
              return (d && d[1]) || 0;
            },
            interpolate: "linear",
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
              axisLabel: "",
              showMaxMin: false
            }
          }
        };

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

        if ($scope.getNvd3Options) {
          Object.assign(options.chart, $scope.getNvd3Options({config:$scope.config}));
        }
        $scope.options = options;
      }

      function formatValue(d, unit) {
        switch (unit) {
        case "bytes":
          var val = mnPrepareQuantityFilter(d, 1024);
          return [mnTruncateTo3DigitsFilter(d/val[0]), val[1]].join('');
        case "percent":
          return  mnTruncateTo3DigitsFilter(d) + "%";
        default: return mnTruncateTo3DigitsFilter(d);
        }
      }

      function onMultiChartDataUpdate(stats) {
        if (!stats) {
          return
        }

        var chartData = [];
        if ($scope.config.specificStat) {
          angular.forEach($scope.config.stats, function (descPath, statName) {
            var desc = mnStatisticsNewService.readByPath(descPath, statName);
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
            var desc = mnStatisticsNewService.readByPath(descPath, name);
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
        if ($scope.chartApi) {
          $scope.chartApi.updateWithData(chartData);
        } else {
          $timeout(function () {
            $scope.chartApi.updateWithData(chartData);
          }, 0)
        }
      }
    }
  }
})();
