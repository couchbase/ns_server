import { MnLifeCycleHooksToStream } from "../mn.core.js";
import mnStatisticsNewService from "./mn_statistics_service.js";
import mnPoolDefault from '../components/mn_pool_default.js';
import {min as d3Min, max as d3Max} from 'd3-array';
import _ from 'lodash';
import {MnTruncateTo3Digits, MnFormatQuantity} from '../mn.pipes.js';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import { MnMultiChart } from './mn_multi_chart_directive.jsx';

class MnStatisticsChartDirective extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      options: null,
      mnUIStats: null,
      chartData: null,
      reloadChartDirective: false
    };
  }

  componentDidUpdate(prevProps, prevState) {
    const vm = this;
    if (vm.state.mnUIStats !== prevState.mnUIStats) {
      vm.onMultiChartDataUpdate(vm.state.mnUIStats);
    }
  }

  componentDidMount() {
    const mnTruncateTo3DigitsFilter = MnTruncateTo3Digits.transform.bind(MnTruncateTo3Digits);
    const mnFormatQuantityFilter = MnFormatQuantity.transform.bind(MnFormatQuantity);

    const vm = this;
    if (!vm.props.config) {
      return;
    }

    var units;
    let poller = vm.props.statsPoller || mnStatisticsNewService.mnAdminStatsPoller;
    let step = mnStatisticsNewService.getChartStep(vm.props.zoom);
    let start = mnStatisticsNewService.getChartStart(vm.props.zoom);

    if (!_.isEmpty(vm.props.config.stats)) {
      units = mnStatisticsNewService.getStatsUnits(vm.props.config.stats);
      vm.title = mnStatisticsNewService.getStatsTitle(vm.props.config.stats);
      vm.desc = mnStatisticsNewService.getStatsDesc(vm.props.config.stats);
      activate();
    }

    function activate() {
      initConfig();
      subscribeToMultiChartData();
      vm.onMultiChartDataUpdate = onMultiChartDataUpdate;
    }

    function subscribeToMultiChartData() {
      poller.subscribeUIStatsPoller({
        bucket: vm.props.bucket || "",
        node: vm.props.node || "all",
        stats: vm.props.config.stats,
        items: vm.props.items,
        zoom: vm.props.zoom,
        specificStat: vm.props.config.specificStat,
        alignTimestamps: true
      }, vm);
    }

    function getChartSize(size) {
      switch (size) {
      case "tiny": return 62;
      case "small": return 102;
      case "medium": return 122;
      case "large": return 312;
      case "extra": return 432;
      default: return 122;
      }
    }

    function initConfig() {
      let options = {
        step: step,
        start: start,
        isPauseEnabled: true,
        enableAnimation: mnPoolDefault.export.getValue().compat.atLeast70 && vm.props.zoom == "minute",
        is70Cluster: mnPoolDefault.export.getValue().compat.atLeast70,
        chart: {
          margin: vm.props.config.margin || {top: 10, right: 36, bottom: 18, left: 44},
          height: getChartSize(vm.props.config.size),
          tooltip: {valueFormatter: formatValue},
          useInteractiveGuideline: true,
          yAxis: [],
          xAxis: {
            tickFormat: function (d) {
              return mnStatisticsNewService.tickMultiFormat(new Date(d));
            }
          },
          noData: "Stats are not found or not ready yet"
        }
      };

      Object.keys(units).forEach(function (unit, index) {
        units[unit] = index;
        options.chart.yAxis[index] = {};
        options.chart.yAxis[index].unit = unit;
        options.chart.yAxis[index].tickFormat = function (d) {
          return formatValue(d, unit);
        };
        options.chart.yAxis[index].domain = getScaledMinMax;
      });

      if (vm.props.mnD3) {
        Object.assign(options.chart, vm.props.mnD3);
      }

      vm.setState({options});
    }

    function formatValue(d, unit) {
      switch (unit) {
      case "percent": return mnTruncateTo3DigitsFilter(d) + "%";
      case "bytes": return mnFormatQuantityFilter(d, 1024);
      case "bytes/sec": return mnFormatQuantityFilter(d, 1024) + "/s";
      case "second": return mnFormatQuantityFilter(d, 1000);
      case "millisecond": return mnFormatQuantityFilter(d / 1000, 1000) + "s"
      case "millisecond/sec": return mnFormatQuantityFilter(d / 1000, 1000) + "/s";
      case "microsecond": return mnFormatQuantityFilter(d / 1000000, 1000) + "s"
      case "nanoseconds": return mnFormatQuantityFilter(d / 1000000000, 1000) + "s";
      case "number": return mnFormatQuantityFilter(d, 1000);
      case "number/sec": return mnFormatQuantityFilter(d, 1000) + "/s";
      default: return mnFormatQuantityFilter(d, 1000);
      }
    }

    function getScaledMinMax(chartData) {
      var min = d3Min(chartData, function (line) {return line.yMin/1.005;});
      var max = d3Max(chartData, function (line) {return line.yMax;});
      if (chartData[0] && chartData[0].unit == "bytes") {
        return [min <= 0 ? 0 : roundDownBytes(min), max == 0 ? 1 : roundUpBytes(max)];
      } else {
        return [min <= 0 ? 0 : roundDown(min), max == 0 ? 1 : roundUp(max)];
      }
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

    function onMultiChartDataUpdate(stats) {
      if (!stats) {
        return;
      }

      if (stats.status == 404) {
        vm.setState({
          options: {
            chart: {
              notFound: true,
              height: getChartSize(vm.props.config.size),
              margin : {top: 0, right: 0, bottom: 0, left: 0},
              type: 'multiChart',
              noData: "Stats are not found or not ready yet"
            }
          },
          chartData: []
        });
        return;
      }

      var chartData = [];

      if (vm.props.config.specificStat) {
        var descPath = Object.keys(vm.props.config.stats)[0];
        var desc = mnStatisticsNewService.readByPath(descPath);
        if (!desc) {
          return;
        }
        var statName = Object.keys(stats.stats)[0];
        var nodes;
        if (vm.props.node == "all") {
          nodes = Object.keys(stats.stats[statName] || {});
          if (!nodes.length) {
            nodes = mnPoolDefault.export.getValue().nodes.map(n => n.hostname);
          }
        } else {
          nodes = [vm.props.node];
        }

        nodes.forEach((nodeName, i) => {
          var previousData = vm.state.chartData && vm.state.chartData[i];
          chartData.push(
            mnStatisticsNewService.buildChartConfig(stats, statName, nodeName,
                                                    nodeName, desc.unit, units[desc.unit],
                                                    previousData, poller.isThisInitCall(),
                                                    start, step))
        });
      } else {
        Object.keys(vm.props.config.stats).forEach((descPath, i) => {
          var desc = mnStatisticsNewService.readByPath(descPath);
          if (!desc) {
            return;
          }

          var statName =
              mnStatisticsNewService.descriptionPathToStatName(descPath, vm.props.items);
          var previousData = vm.state.chartData && vm.state.chartData[i];

          chartData.push(
            mnStatisticsNewService.buildChartConfig(stats, statName, vm.props.node,
                                                    desc.title, desc.unit, units[desc.unit],
                                                    previousData, poller.isThisInitCall(),
                                                    start, step));

        });
      }

      if (vm.state.chartData) {
        vm.state.chartData.forEach((v, i) => {
          if (!chartData[i]) {
            return;
          }
          chartData[i].disabled = v.disabled;
        });
      }
      vm.setState({chartData});
    }
  }

  render() {
    const vm = this;
    const { options, chartData } = vm.state;
    const { statsPoller, api } = vm.props;
    const { title, desc } = vm;

    return (
      <div className={vm.props.className} onClick={vm.props.onClick}>
        <div className="row" style={{ pointerEvents: 'none' }}>
          <OverlayTrigger
            placement="auto-end"
            delay={{ show: 500, hide: 0 }}
            overlay={
              <Tooltip id={`tooltip-${title}`}>
                {/* Sanitizers are necessary when the markup comes from user input,
                or from an external service. They're not needed if the markup
                comes entirely from your own code. In this case desc is hardcoded */}
                <div dangerouslySetInnerHTML={{ __html: desc }} />
              </Tooltip>
            }
          >
            <span 
              className="chart-title cursor-pointer"
              style={{ pointerEvents: 'auto' }}
            >
              {title}
            </span>
          </OverlayTrigger>
          <span>&nbsp;</span>
        </div>
        
        {options && (
          <MnMultiChart
            syncScope={true}
            style={{ display: 'block' }}
            statsPoller={statsPoller}
            api={api}
            options={options}
            data={chartData}
          />
        )}
      </div>
    );
  }
}

export {MnStatisticsChartDirective}