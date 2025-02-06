import { ModalContext } from '../uib/template/modal/window.and.backdrop.jsx';
import { MnLifeCycleHooksToStream } from '../mn.core.js';
import mnStatisticsNewService from './mn_statistics_service.js';
import mnUserRolesService from './mn_user_roles_service.js';
import mnHelper from '../components/mn_helper.js';
import { MnStatisticsChartBuilderDelete } from './mn_statistics_chart_builder_delete.jsx';
import { MnStatisticsChartBuilderComponent } from './mn_statistics_chart_builder_controller.jsx';
import { MnStatisticsChartDirective } from './mn_statistics_chart_directive.jsx';
import { MnStatisticsDetailedChart } from './mn_statistics_detailed_chart_controller.jsx';
import { equals } from 'ramda';

class MnStatisticsChartsChart extends MnLifeCycleHooksToStream {
  static contextType = ModalContext;

  constructor(props) {
    super(props);

    this.state = {
      reloadChartDirective: false,
    };
  }

  componentDidUpdate(prevProps) {
    const vm = this;

    if (
      !equals(
        prevProps.chartsById?.[vm.props.chartID],
        vm.props.chartsById?.[vm.props.chartID]
      )
    ) {
      vm.onItemChange();
    }
  }

  componentWillMount() {
    var vm = this;
    const { statisticsNewCtl, mnStatsGroupsCtl } = vm.props;
    const { openModal } = vm.context;

    vm.deleteChart = deleteChart;
    vm.editChart = editChart;
    vm.openDetailedChartDialog = openDetailedChartDialog;
    vm.getChart = getChart;
    vm.onItemChange = onItemChange;
    vm.api = {};

    function onItemChange() {
      vm.setState({ reloadChartDirective: true });
      setTimeout(function () {
        vm.setState({ reloadChartDirective: false });
        mnStatsGroupsCtl.maybeShowItemsControls();
      }, 0);
    }

    function getChart(chartID) {
      return (
        statisticsNewCtl.state.chartsById &&
        statisticsNewCtl.state.chartsById[chartID]
      );
    }

    function deleteChart(chartID) {
      vm.showChartControls = false;
      openModal({
        component: MnStatisticsChartBuilderDelete,
      }).then(
        function () {
          mnStatisticsNewService.deleteChart(chartID);
          mnUserRolesService.saveDashboard();
          mnStatsGroupsCtl.maybeShowItemsControls();
        },
        () => {}
      );
    }

    function editChart(group, scenario, chartID) {
      vm.showChartControls = false;
      openModal({
        component: MnStatisticsChartBuilderComponent,
        props: {
          poolDefault: vm.props.poolDefault,
        },
        resolve: {
          chart: mnHelper.wrapInFunction(vm.getChart(chartID)),
          group: mnHelper.wrapInFunction(group),
          scenario: mnHelper.wrapInFunction(scenario),
        },
      }).then(
        function () {
          mnUserRolesService.saveDashboard();
          onItemChange();
        },
        () => {}
      );
    }

    function openDetailedChartDialog(chartID) {
      openModal({
        component: MnStatisticsDetailedChart,
        windowClass: 'chart-overlay',
        resolve: {
          items: mnHelper.wrapInFunction(vm.props.items),
          chart: mnHelper.wrapInFunction(vm.getChart(chartID)),
        },
      }).then(null, () => {});
    }
  }

  render() {
    const vm = this;
    const { group, statisticsNewCtl, mnStatsGroupsCtl, chartID, chart, items } =
      vm.props;

    return (
      <div
        key={chartID}
        className={`statistics-${chart?.size || 'small'} panel relative`}
      >
        {!chart?.preset && (
          <div className="chart-controls">
            <span
              title="delete chart"
              className="icon fa-trash"
              onClick={() => vm.deleteChart(chartID)}
            />
            {chart && (
              <span
                title="edit chart"
                className="icon fa-edit"
                onClick={() =>
                  vm.editChart(
                    group,
                    statisticsNewCtl.getSelectedScenario(),
                    chartID
                  )
                }
              />
            )}
          </div>
        )}
        {!chart ? (
          <div className="statistics-not-available">Chart not available</div>
        ) : (
          !vm.state.reloadChartDirective &&
          !mnStatsGroupsCtl.state.reloadChartDirective && (
            <MnStatisticsChartDirective
              onClick={() => {
                vm.api?.chart?.inititalized &&
                  vm.openDetailedChartDialog(chartID);
              }}
              statsPoller={statisticsNewCtl.mnAdminStatsPoller}
              bucket={statisticsNewCtl.bucket}
              zoom={statisticsNewCtl.zoom}
              node={statisticsNewCtl.node}
              items={items}
              api={vm.api}
              config={chart}
            />
          )
        )}
      </div>
    );
  }
}

export { MnStatisticsChartsChart };
