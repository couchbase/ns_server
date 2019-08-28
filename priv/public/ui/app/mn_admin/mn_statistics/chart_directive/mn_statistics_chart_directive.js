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
      var options;

      if (!_.isEmpty($scope.config.stats)) {
        units = mnStatisticsNewService.getStatsUnits($scope.config.stats);
        $scope.title = mnStatisticsNewService.getStatsTitle($scope.config.stats);
        $scope.desc = mnStatisticsNewService.getStatsDesc($scope.config.stats);
        activate();
      }

      function defaultValueFormatter(d, s, c, g, f, a) {
        if (c.data[1] == undefined) {
          return "N/A"
        }
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
          if (source.element[0] !== $element[0] && $element.find("svg")[0] &&
              source.api.getScope().chart && !source.api.getScope().options.chart.notFound) {
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

      function getChartSize(size) {
        switch (size) {
        case "small": return 170;
        case "medium": return 170;
        case "large": return 330;
        default: return 150;
        }
      }

      function initConfig() {
        options = {
          chart: {
            type: 'multiChart',
            margin : {top: 32, right: 40, bottom: 40, left: 40},
            height: getChartSize($scope.config.size),
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
            noData: "No Data"
          }
        };

        var index = 0;
        _.forEach(units, function (val, unit) {
          index ++;
          units[unit] = index;
          options.chart["yAxis" + index] = {};
          options.chart["yAxis" + index].ticks = [];
          options.chart["yAxis" + index].showMaxMin = true;
          options.chart["yAxis" + index].axisLabel = unit; //hack that is involved in order to show current stats value in tooltip correctly
          options.chart["yAxis" + index].tickFormatMaxMin = function (d) {
            return formatMaxMin(d, unit);
          }
        });

        if ($scope.getNvd3Options) {
          Object.assign(options.chart, $scope.getNvd3Options({config:$scope.config}));
        }
      }

      function formatMaxMin(d, unit) {
        switch (unit) {
        case "bytes":
          var val = mnPrepareQuantityFilter(d, 1024);
          return d3.format(".2s")(d/val[0]) + val[1];
        case "percent":
          return d3.format(".0%")(d / 100);
        case "second":
          return d3.format(".2s")(d) + 's';
        case "millisecond":
          return d3.format(".2s")(d / 1000) + 's';
        case "microsecond":
          return d3.format(".2s")(d / 1000000) + 's';
        case "nanoseconds":
          return d3.format(".2s")(d / 1000000000) + 's';
        default:
          return d3.format(".2s")(d);
        }
      }

      function formatValue(d, unit) {
        switch (unit) {
        case "bytes":
          var val = mnPrepareQuantityFilter(d, 1024);
          return [mnTruncateTo3DigitsFilter(d/val[0]), val[1]].join('');
        case "percent":
          return  mnTruncateTo3DigitsFilter(d) + "%";
        case "millisecond":
          return d3.format(".2s")(d / 1000) + 's';
        case "microsecond":
          return d3.format(".2s")(d / 1000000) + 's';
        case "nanoseconds":
          return d3.format(".2s")(d / 1000000000) + 's';
        default: return mnTruncateTo3DigitsFilter(d);
        }
      }

      function getScaledMinMax(chartData, unit) {
        var min = d3.min(chartData, function (line) {return line.min/1.005;});
        var max = d3.max(chartData, function (line) {return line.max;});
        if (unit == "bytes")
          return [min <= 0 ? 0 : roundDownBytes(min), max == 0 ? 1 : roundUpBytes(max)];
        else
          return [min <= 0 ? 0 : roundDown(min), max == 0 ? 1 : roundUp(max)];
      }

      // make 2nd digit either 0 or 5
      function roundUp(num) {
        var mag = Math.pow(10,Math.floor(Math.log10(num)));
        return(mag*Math.ceil(2*num/mag)/2);
      }

      function roundDown(num) {
        var mag = Math.pow(10,Math.floor(Math.log10(num)));
        return(mag*Math.floor(2*num/mag)/2);
      }

      function roundUpBytes(num) { // round up 3rd digit to 0
        var mag = Math.trunc(Math.log2(num)/10);
        var base_num = num/Math.pow(2,mag*10); // how many KB, MB, GB, TB, whatever
        var mag10 = Math.pow(10,Math.floor(Math.log10(base_num))-1);
        return Math.ceil(base_num/mag10) * mag10 * Math.pow(2,mag*10);
      }

      function roundDownBytes(num) {
        var mag = Math.trunc(Math.log2(num)/10);
        var base_num = num/Math.pow(2,mag*10);
        var mag10 = Math.pow(10,Math.floor(Math.log10(base_num))-1);
        return Math.floor(base_num/mag10) * mag10 * Math.pow(2,mag*10);
      }

      function updateYAxisDomain(chartData) {
        var chart = $scope.chartApi.getScope().chart;
        _.forEach(units, function (i, unit) {
          chart["yDomain" + i](getScaledMinMax(chartData, unit));
        });
      }

      function setYAxisDomain(chartData) {
        _.forEach(units, function (i, unit) {
          options.chart["yDomain" + i] = getScaledMinMax(chartData, unit);
        });
      }

      function onMultiChartDataUpdate(stats) {
        if (!stats) {
          return;
        }

        if (stats.status == 404) {
          $scope.options = {
            chart: {
              notFound: true,
              margin : {top: 32, right: 40, bottom: 40, left: 40},
              type: 'multiChart',
              noData: "Statistics could not be found."
            }
          };
          $scope.chartData = [];
          return;
        }

        var chartData = [];
        if ($scope.config.specificStat) {
          angular.forEach($scope.config.stats, function (descPath, statName) {
            var desc = mnStatisticsNewService.readByPath(descPath, statName);
            angular.forEach(stats.data.samples, function (nodeStat, nodeName) {
              chartData.push({
                type: 'line',
                unit: desc.unit,
                max: d3.max(nodeStat || []),
                min: d3.min(nodeStat || []),
                yAxis: units[desc.unit],
                key: nodeName,
                values: _.zip(nodeStat.timestamps, nodeStat || [])
              });
            });
          });

        } else {
          angular.forEach($scope.config.stats, function (descPath, name) {
            var desc = mnStatisticsNewService.readByPath(descPath, name);
            var timestamps = stats.data.samples[Object.keys(stats.data.samples)[0]].timestamps;
            chartData.push({
              type: 'line',
              unit: desc.unit,
              max: d3.max(stats.data.samples[name] || []),
              min: d3.min(stats.data.samples[name] || []),
              yAxis: units[desc.unit],
              key: !stats.data.samples[name] ? (desc.title + " (not found)") : desc.title,
              values: _.zip(timestamps, stats.data.samples[name] || [])
            });
          });
        }
        if ($scope.chartData) {
          $scope.chartData.forEach(function (v, i) {
            if (!chartData[i]) {
              return;
            }
            chartData[i].disabled = v.disabled;
          });
        }
        if ($scope.chartApi && $scope.chartApi.getScope().chart) {
          updateYAxisDomain(chartData);
          $scope.chartData = chartData;
        } else {
          $timeout(function () {
            setYAxisDomain(chartData);
            $scope.options = options;
            $scope.chartData = chartData;
          }, 0);
        }
      }
    }
  }
})();
