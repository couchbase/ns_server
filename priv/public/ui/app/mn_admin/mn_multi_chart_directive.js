import _ from "/ui/web_modules/lodash.js"

export default mnMultiChartDirective;

function mnMultiChartDirective($window, mnD3Service) {
  return {
    restrict: 'AE',
    scope: {
      data: "=?",
      options: "=?",
      api: "=?",
      syncScope: "=?"
    },
    controller: controller
  };

  function controller($element, $scope, $timeout) {
    var chart = new mnD3Service.mnD3Tooltip($scope.options, $element, function () {
      angular.element($window).on('resize', chart.throttledResize);
      chart.resize();
      if ($scope.syncScope) {
        syncTooltipsAndPauseCharts();
      }
      if ($scope.options.chart.showFocus) {
        addFocusChart();
      }
      if (this.cht.showLegends) {
        this.drawLegends();
      }
    });

    $scope.$watch("data", chart.updateData.bind(chart));

    $scope.$on("$destroy", function () {
      angular.element($window).off('resize', chart.throttledResize);
      chart.destroy();
    });

    if ($scope.api) {
      $scope.api.chart = chart;
    }

    function addFocusChart() {
      var focusChartOpt = _.cloneDeep($scope.options);
      focusChartOpt.chart.height = 80;
      focusChartOpt.chart.hideTicks = true;
      focusChartOpt.chart.showFocus = false;
      var chartF = new mnD3Service.mnD3Focus(focusChartOpt, $element, chart);
      angular.element($window).on('resize', chartF.throttledResize);

      $scope.$watch("data", chartF.updateData.bind(chartF));

      chart.rootEl.on("toggleLegend", function (opt) {
        chartF.updateData(chartF.data);
      });

      if ($scope.api) {
        $scope.api.chartF = chartF;
      }

      $scope.$on("$destroy", function () {
        angular.element($window).off('resize', chartF.throttledResize);
        chartF.destroy();
      });
    }

    function syncTooltipsAndPauseCharts() {
      let mnPauseStats = false;
      let resumeStatsTimer;
      let chartNode = chart.tipBox.node();

      let throttledSync = _.throttle(function (e) {
        if (e.bubbles) {
          $scope.syncScope.$broadcast("syncTooltips", {element: $element,
                                                       event: e,
                                                       chart: chart});
        }
      }, 10, {leading: true});

      let throttledPause = _.throttle(function (e) {
        if (e.bubbles) {
          $scope.syncScope.$broadcast("mnStatsCancelTimer");
          if (!mnPauseStats) {
            $scope.syncScope.$broadcast("mnPauseStats");
            mnPauseStats = true;
          }
        }
      }, 10, {leading: true});

      let throttledResume = _.throttle(function (e) {
        if (mnPauseStats && e.bubbles) {
          resumeStatsTimer && $timeout.cancel(resumeStatsTimer);
          resumeStatsTimer = $timeout(function () {
            $scope.syncScope.$broadcast("mnResumeStats");
            mnPauseStats = false;
          }, 1000);
        }
      }, 10, {leading: true});

      angular.element(chartNode).on("mousemove mouseup mousedown mouseout", throttledSync);
      angular.element(chartNode).on("mousemove", throttledPause);
      angular.element(chartNode).on("mouseout", throttledResume);

      $scope.$on("mnStatsCancelTimer", function () {
        resumeStatsTimer && $timeout.cancel(resumeStatsTimer);
      });

      $scope.$on("mnPauseStats", function () {
        mnPauseStats = true;
      });

      $scope.$on("mnResumeStats", function () {
        mnPauseStats = false;
      });

      $scope.$on("$destroy", function () {
        angular.element(chartNode).off("mousemove mouseup mousedown mouseout", throttledSync);
        angular.element(chartNode).off("mousemove", throttledPause);
        angular.element(chartNode).off("mouseout", throttledResume);
      });

      $scope.$on("syncTooltips", function (e, source) {
        if (source.element[0] !== $element[0]) {
          var sourcePos = source.chart.tipBoxRect;
          var elementPos = chart.tipBoxRect;
          var sourceGraphRelativeX = source.event.clientX - sourcePos.x;
          var sourceGraphRelativeY = source.event.clientY - sourcePos.y;

          var interpolateX = sourcePos.width / sourceGraphRelativeX;
          var clientX = elementPos.x + (elementPos.width / interpolateX);

          var interpolateY = sourcePos.height / sourceGraphRelativeY;
          var clientY = elementPos.y + (elementPos.height / interpolateY);

          source.chart.disableTooltip(false);
          chart.disableTooltip(true);

          chart.tipBox.node().dispatchEvent(createEvent(
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
  }
}
