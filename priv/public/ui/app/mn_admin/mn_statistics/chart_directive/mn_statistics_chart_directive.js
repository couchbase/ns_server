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

  function mnStatisticsNewChartDirective(mnStatisticsNewService, mnStatisticsDescriptionService, $uibModal, $state, mnPrepareQuantityFilter, mnTruncateTo3DigitsFilter, $rootScope, mnHelper, $timeout, $window) {
    return {
      restrict: 'AE',
      templateUrl: 'app/mn_admin/mn_statistics/chart_directive/mn_statistics_chart_directive.html',
      scope: {
        syncScope: "=?",
        config: "=",
        getNvd3Options: "&?",
        bucket: "@",
        zoom: "@"
      },
      controller: controller
    };

    function controller($scope, $element) {
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
        $scope.$on("$destroy", function () {
          if (!$scope.chartApi || !$scope.chartApi.getScope().chart) {
            return;
          }
          //MB-34897
          //https://github.com/krispo/angular-nvd3/issues/550
          var tooltipId = $scope.chartApi.getScope().chart.interactiveLayer.tooltip.id();
          angular.element(document.querySelector("#" + tooltipId)).remove();
        });
        initConfig();
        subscribeToMultiChartData();
        if ($scope.syncScope) {
          syncTooltips();
        }
      }

      function syncTooltips() {
        $element.on("mousemove mouseup mousedown mouseout", _.debounce(function (e) {
          $scope.syncScope.$broadcast("syncTooltips", {
            element: $element,
            event: e,
            api: $scope.chartApi
          });
        }, 2, {leading:true}));

        $scope.$on("syncTooltips", function (e, source) {
          if (source.element[0] !== $element[0] && $element.find("svg")[0]) {
            var sourcePos = source.element[0].getBoundingClientRect();
            var elementPos = $element[0].getBoundingClientRect();
            var sourceMargin = source.api.getScope().chart.margin();
            var elementMargin = $scope.chartApi.getScope().chart.margin();
            var sourceGraphWidth = sourcePos.width - sourceMargin.right - sourceMargin.left;
            var elementGraphWidth = elementPos.width - elementMargin.right - elementMargin.left;
            var sourceGraphRelativeX = source.event.clientX - sourcePos.x - sourceMargin.left;

            var interX = sourceGraphWidth / sourceGraphRelativeX;
            var clientX  = (elementPos.x + elementMargin.right) + (elementGraphWidth / interX);

            var interY =  sourcePos.height / (source.event.clientY - sourcePos.y);
            var clientY  = elementPos.y + (elementPos.height / interY);

            source.api.getScope().chart.interactiveLayer.tooltip.enabled(true);
            $scope.chartApi.getScope().chart.interactiveLayer.tooltip.enabled(false);

            $element.find("svg")[0].dispatchEvent(createEvent(
	      source.event.type,
              clientX,
              clientY
	    ));
          }
        });
      }

      function createEvent(type, clientX, clientY){
        var event = new MouseEvent(type, {
          view: $window,
          bubbles: false,
          cancelable: true,
          clientX: clientX,
          clientY: clientY
        });
        return event;
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
        if ($scope.chartData) {
          $scope.chartData.forEach(function (v, i) {
            chartData[i].disabled = v.disabled;
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
