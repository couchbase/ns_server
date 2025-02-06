import React from 'react';
import _ from 'lodash';
import { MnLifeCycleHooksToStream } from '../mn.core.js';
import mnD3Service from './mn_d3_service.js';
import { MnHelperReactService } from '../mn.helper.react.service';

class MnMultiChart extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.chartRef = React.createRef();
  }

  componentDidUpdate(prevProps) {
    const vm = this;
    if (prevProps.data !== vm.props.data) {
      vm.chart.updateData(vm.props.data);
      if (vm.chartF) {
        vm.chartF.updateData(vm.props.data);
      }
    }
  }

  componentDidMount() {
    const vm = this;
    const { options, syncScope, statsPoller, api } = vm.props;
    vm.chart = new mnD3Service.mnD3Tooltip(
      options,
      vm.chartRef.current,
      function () {
        window.addEventListener('resize', vm.chart.throttledResize);
        vm.chart.resize();
        if (syncScope) {
          syncTooltipsAndPauseCharts();
        }
        if (options.chart.showFocus) {
          addFocusChart();
        }
        if (this.cht.showLegends) {
          this.drawLegends();
        }
      }
    );

    vm.mnOnDestroy.subscribe(() => {
      window.removeEventListener('resize', vm.chart.throttledResize);
      vm.chart.destroy();
    });

    if (api) {
      api.chart = vm.chart;
    }

    function addFocusChart() {
      var focusChartOpt = _.cloneDeep(options);
      focusChartOpt.chart.height = 80;
      focusChartOpt.chart.hideTicks = true;
      focusChartOpt.chart.showFocus = false;
      vm.chartF = new mnD3Service.mnD3Focus(
        focusChartOpt,
        vm.chartRef.current,
        vm.chart
      );
      window.addEventListener('resize', vm.chartF.throttledResize);

      vm.chart.rootEl.on('toggleLegend', function () {
        vm.chartF.updateData(vm.chartF.data);
      });

      if (api) {
        api.chartF = vm.chartF;
      }

      vm.mnOnDestroy.subscribe(() => {
        window.removeEventListener('resize', vm.chartF.throttledResize);
        vm.chartF.destroy();
      });
    }

    function syncTooltipsAndPauseCharts() {
      let resumeStatsTimer;
      let chartNode = vm.chart.tipBox.node();
      let cancelStatsTimer = () =>
        MnHelperReactService.rootScopeEmitter.emit('mnStatsCancelTimer');

      let throttledSync = _.throttle(
        function (e) {
          if (e.bubbles) {
            MnHelperReactService.rootScopeEmitter.emit('syncTooltips', {
              element: vm.chartRef.current,
              event: e,
              chart: vm.chart,
            });
          }
        },
        60,
        { leading: true }
      );

      let throttledPause = _.throttle(
        function () {
          cancelStatsTimer();
          if (!statsPoller.heartbeat.isPaused) {
            statsPoller.heartbeat.pause();
          }
        },
        10,
        { leading: true }
      );

      let throttledResume = _.throttle(
        function (e) {
          if (statsPoller.heartbeat.isPaused && e.bubbles) {
            resumeStatsTimer && clearTimeout(resumeStatsTimer);
            resumeStatsTimer = setTimeout(function () {
              statsPoller.heartbeat.resume();
            }, 1000);
          }
        },
        10,
        { leading: true }
      );

      chartNode.addEventListener('mousemove', throttledSync);
      chartNode.addEventListener('mouseup', throttledSync);
      chartNode.addEventListener('mousedown', throttledSync);
      chartNode.addEventListener('mouseout', throttledSync);
      chartNode.addEventListener('mouseenter', throttledPause);
      chartNode.addEventListener('mouseout', throttledResume);

      MnHelperReactService.rootScopeEmitter.on(
        'mnStatsCancelTimer',
        function () {
          resumeStatsTimer && clearTimeout(resumeStatsTimer);
        }
      );

      vm.mnOnDestroy.subscribe(() => {
        document.removeEventListener('visibilitychange', cancelStatsTimer);
      });

      MnHelperReactService.rootScopeEmitter.on('syncTooltips', function (e) {
        const source = e;
        if (source.element !== vm.chartRef.current) {
          var sourcePos = source.chart.tipBoxRect;
          var elementPos = vm.chart.tipBoxRect;
          var sourceGraphRelativeX = source.event.clientX - sourcePos.x;
          var sourceGraphRelativeY = source.event.clientY - sourcePos.y;

          var interpolateX = sourcePos.width / sourceGraphRelativeX;
          var clientX = elementPos.x + elementPos.width / interpolateX;

          var interpolateY = sourcePos.height / sourceGraphRelativeY;
          var clientY = elementPos.y + elementPos.height / interpolateY;

          source.chart.disableTooltip(false);
          vm.chart.disableTooltip(true);

          vm.chart.tipBox
            .node()
            .dispatchEvent(createEvent(source.event.type, clientX, clientY));
        }
      });

      function createEvent(type, clientX, clientY) {
        var event = new MouseEvent(type, {
          view: window,
          bubbles: false,
          cancelable: true,
          clientX: clientX,
          clientY: clientY,
        });
        return event;
      }
    }
  }

  render() {
    return <div ref={this.chartRef} className="mn-multi-chart"></div>;
  }
}

export { MnMultiChart };
