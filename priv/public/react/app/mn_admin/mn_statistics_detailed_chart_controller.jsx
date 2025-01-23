import {MnHelperReactService} from "../mn.helper.react.service.js";
import {MnLifeCycleHooksToStream} from "../mn.core.js";
import { UIRouter }  from "mn.react.router";
import mnStatisticsNewService from "./mn_statistics_service.js";
import { MnSelect } from "../components/directives/mn_select/mn_select.jsx";
import { MnStatisticsChartDirective } from './mn_statistics_chart_directive.jsx';

class MnStatisticsDetailedChart extends MnLifeCycleHooksToStream {

  constructor(props) {
    super(props);

    this.state = {
      reloadChartDirective: false
    };
  }

  componentWillMount() {
    var vm = this;
    const { chart, items } = vm.props;
    vm.chart = Object.assign({}, chart, {size: "extra"});

    vm.items = items;
    vm.onSelectZoom = onSelectZoom;
    vm.bucket = UIRouter.globals.params.scenarioBucket;
    vm.zoom = UIRouter.globals.params.scenarioZoom !== "minute" ? UIRouter.globals.params.scenarioZoom : "hour";
    vm.node = UIRouter.globals.params.statsHostname;
    vm.options = {showFocus: true, showTicks: true, showLegends: true};
  
    MnHelperReactService.rootScopeEmitter.emit("mnStatsCancelTimer");
  
    mnStatisticsNewService.mnAdminStatsPoller.heartbeat.pause();
    vm.statsPoller = mnStatisticsNewService.createStatsPoller(vm);
    vm.statsPoller.heartbeat.setInterval(mnStatisticsNewService.defaultZoomInterval(vm.zoom));
  
    function onSelectZoom({selectedOption}) {
      vm.options.showFocus = selectedOption !== "minute";
      let interval = mnStatisticsNewService.defaultZoomInterval(selectedOption);
      vm.statsPoller.heartbeat.setInterval(interval);
      vm.setState({reloadChartDirective: true});
      setTimeout(function () {
        vm.setState({reloadChartDirective: false});
      }, 0);
      vm.zoom = selectedOption;
    }
    
    vm.mnOnDestroy.subscribe(() => {
      mnStatisticsNewService.mnAdminStatsPoller.heartbeat.resume();
    });
  }

  render() {
    const {zoom, bucket, node, options, items, chart, statsPoller} = this;
    const {reloadChartDirective} = this.state;
    
    return (
      <div className="panel-content">
        <div className="row flex-center width-10 margin-auto margin-top-neg-half">
          <MnSelect
            className="fix-width-1-5 margin-0"
            value={zoom}
            onSelect={this.onSelectZoom}
            values={['minute', 'hour', 'day', 'week', 'month']}
            capitalize={true}
          />
        </div>
        {/* TODO: check if we correctly pass className */}
        {!reloadChartDirective && (
          <MnStatisticsChartDirective
            className={`${zoom}-chart detailed-chart`}
            statsPoller={statsPoller}
            bucket={bucket}
            zoom={zoom}
            node={node || 'all'}
            mnD3={options}
            items={items}
            config={chart}
          />
        )}
      </div>
    );
  }
}

export {MnStatisticsDetailedChart};
