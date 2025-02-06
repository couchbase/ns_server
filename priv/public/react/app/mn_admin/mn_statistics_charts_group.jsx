import { ModalContext } from '../uib/template/modal/window.and.backdrop.jsx';
import { MnLifeCycleHooksToStream } from '../mn.core.js';
import { MnSelect } from '../components/directives/mn_select/mn_select.jsx';
// import { MnStatisticsChart } from "./mn_statistics_chart.jsx";
import { MnStatisticsGroupDelete } from './mn_statistics_group_delete.jsx';
import mnStatisticsNewService from './mn_statistics_service.js';
import mnUserRolesService from './mn_user_roles_service.js';
import mnStoreService from '../components/mn_store_service.js';
import mnHelper from '../components/mn_helper.js';
import { MnStatisticsChartsChart } from './mn_statistics_charts_chart.jsx';

class MnStatisticsChartsGroup extends MnLifeCycleHooksToStream {
  static contextType = ModalContext;

  constructor(props) {
    super(props);

    this.state = {
      reloadChartDirective: false,
      updateState: 0,
      showGroupControls: false,
      name: props.group.name,
      items: {
        eventing: null,
        xdcr: null,
        index: null,
        kv: null,
        fts: null,
      },
    };
  }

  updateState = () => {
    this.setState({ updateState: this.state.updateState + 1 });
  };

  componentDidUpdate(prevProps) {
    const vm = this;
    const { statisticsNewCtl } = vm.props;
    const prevStatisticsNewCtl = prevProps.statisticsNewCtl;

    if (
      statisticsNewCtl.eventingItems?.values[0] !==
        prevStatisticsNewCtl.eventingItems?.values[0] ||
      statisticsNewCtl.xdcrItems?.values[0] !==
        prevStatisticsNewCtl.xdcrItems?.values[0] ||
      statisticsNewCtl.indexItems?.values[0] !==
        prevStatisticsNewCtl.indexItems?.values[0] ||
      statisticsNewCtl.viewItems?.values[0] !==
        prevStatisticsNewCtl.viewItems?.values[0] ||
      statisticsNewCtl.ftsItems?.values[0] !==
        prevStatisticsNewCtl.ftsItems?.values[0]
    ) {
      vm.onItemChange();
    }
  }

  componentWillMount() {
    var vm = this;
    const { statisticsNewCtl, groupID } = vm.props;
    const { openModal } = vm.context;
    vm.hideGroupControls = hideGroupControls;
    vm.onGroupNameBlur = onGroupNameBlur;
    vm.onGroupFocus = onGroupFocus;
    vm.onGroupSubmit = onGroupSubmit;
    vm.onGroupDelete = onGroupDelete;
    vm.deleteGroup = deleteGroup;
    vm.maybeShowItemsControls = maybeShowItemsControls;

    vm.saveDashboard = mnUserRolesService.saveDashboard;
    vm.onGroupNameChange = onGroupNameChange;

    mnHelper.initializeDetailsHashObserver(vm, 'openedGroups', '.');

    vm.enabledItems = {};
    vm.getGroup = getGroup;
    vm.onItemChange = onItemChange;

    maybeShowItemsControls();

    function getGroup() {
      return (
        statisticsNewCtl.state.groupsById &&
        statisticsNewCtl.state.groupsById[groupID]
      );
    }

    function onItemChange() {
      vm.setState({ reloadChartDirective: true });
      setTimeout(function () {
        vm.setState({ reloadChartDirective: false });
        maybeShowItemsControls();
      }, 0);
    }

    function maybeShowItemsControls() {
      var items = {};
      ((vm.getGroup() || {}).charts || []).forEach(function (chartID) {
        var stats = mnStoreService.store('charts').get(chartID)
          ? mnStoreService.store('charts').get(chartID).stats
          : {};
        var chartStats = Object.keys(stats);
        chartStats.forEach(function (statPath) {
          if (statPath.includes('@items')) {
            items[statPath.split('.')[0]] = true;
          }
        });
      });
      vm.enabledItems = items;
    }

    function deleteGroup(groupID) {
      openModal({
        component: MnStatisticsGroupDelete,
      }).then(
        function () {
          mnStatisticsNewService.deleteGroup(groupID);
          mnUserRolesService.saveDashboard();
        },
        () => {}
      );
    }

    function onGroupDelete(groupID) {
      vm.onControlClick = true;
      deleteGroup(groupID);
      hideGroupControls();
    }

    function onGroupSubmit() {
      vm.initName = vm.getGroup().name;
      mnUserRolesService.saveDashboard();
      hideGroupControls();
      vm.focusOnSubmit = true;
    }

    function onGroupFocus() {
      vm.setState({ showGroupControls: true });
      vm.initName = vm.getGroup().name;
    }

    function onGroupNameBlur() {
      if (!vm.onControlClick) {
        vm.setState({ showGroupControls: false });
        vm.getGroup().name = vm.initName;
        mnStoreService.store('groups').put(vm.getGroup());
      }
    }

    function hideGroupControls() {
      if (vm.onControlClick) {
        vm.onControlClick = false;
        onGroupNameBlur();
      }
    }

    function onGroupNameChange(name) {
      vm.getGroup().name = name;
      mnStoreService.store('groups').put(vm.getGroup());
    }
  }

  render() {
    const vm = this;
    const { rbac, groupID, group, statisticsNewCtl, chartsById } = vm.props;

    return (
      <div id={`group-${groupID}`} className="charts-group">
        <div
          onClick={() => {
            vm.toggleDetails(groupID);
          }}
          className={`charts-group-row disclosure nowrap has-hover ${
            vm.isDetailsOpened(groupID) ? 'disclosed' : ''
          }`}
        >
          {!group.preset ? (
            <form
              className="inline"
              onMouseLeave={() => vm.hideGroupControls()}
              onClick={(e) => e.stopPropagation()}
              onSubmit={(e) => {
                e.preventDefault();
                vm.onGroupSubmit();
              }}
            >
              <input
                value={vm.state.name}
                onChange={(e) => {
                  vm.setState({ name: e.target.value });
                  vm.onGroupNameChange(e.target.value);
                }}
                autoCorrect="off"
                spellCheck="false"
                autoCapitalize="off"
                type="text"
                className="charts-group-name"
                onFocus={vm.onGroupFocus}
                onBlur={vm.onGroupNameBlur}
                size={group.name.length + 3}
              />
              {vm.state.showGroupControls && (
                <>
                  <button
                    type="submit"
                    title="save group name"
                    onMouseDown={() => (vm.onControlClick = true)}
                    className="light adder"
                  >
                    <span className="icon fa-check"></span>
                  </button>
                  <button
                    title="delete group"
                    className="light dashboard-delete margin-0"
                    onMouseDown={() => vm.onGroupDelete(groupID)}
                  >
                    <span className="icon fa-trash"></span>
                  </button>
                </>
              )}
            </form>
          ) : (
            <span className="charts-preset-group-name ellipsis">
              {group.name}
            </span>
          )}

          {vm.isDetailsOpened(groupID) && (
            <div
              className="chart-group-row-items"
              onClick={(e) => e.stopPropagation()}
            >
              {vm.enabledItems?.['@index-'] &&
                statisticsNewCtl.state.indexItems?.values?.length && (
                  <div className="row flex-wrap">
                    <strong className="margin-right-quarter">Indexes</strong>
                    <MnSelect
                      className="inline max-width-2"
                      value={
                        vm.state.items?.index ||
                        statisticsNewCtl.state.indexItems?.values[0]
                      }
                      values={statisticsNewCtl.state.indexItems?.values}
                      labels={statisticsNewCtl.state.indexItems?.labels}
                      hasSearch={true}
                      horizontalAlign="right"
                      onSelect={({ selectedOption }) => {
                        vm.setState({
                          items: {
                            ...vm.state.items,
                            index: selectedOption,
                          },
                        });
                      }}
                    />
                  </div>
                )}

              {vm.enabledItems?.['@kv-'] &&
                statisticsNewCtl.state.viewItems?.values?.length && (
                  <div className="row flex-wrap margin-left-1">
                    <strong className="margin-right-quarter">Views</strong>
                    <MnSelect
                      className="inline max-width-2"
                      value={
                        vm.state.items?.kv ||
                        statisticsNewCtl.state.viewItems?.values[0]
                      }
                      values={statisticsNewCtl.state.viewItems?.values}
                      labels={statisticsNewCtl.state.viewItems?.labels}
                      horizontalAlign="right"
                      onSelect={({ selectedOption }) => {
                        vm.setState({
                          items: {
                            ...vm.state.items,
                            kv: selectedOption,
                          },
                        });
                      }}
                    />
                  </div>
                )}

              {vm.enabledItems?.['@xdcr-'] &&
                statisticsNewCtl.state.xdcrItems?.values?.length && (
                  <div className="row flex-wrap margin-left-1">
                    <strong className="margin-right-quarter">
                      Replications
                    </strong>
                    <MnSelect
                      className="inline max-width-2"
                      value={
                        vm.state.items?.xdcr ||
                        statisticsNewCtl.state.xdcrItems?.values[0]
                      }
                      values={statisticsNewCtl.state.xdcrItems?.values}
                      labels={statisticsNewCtl.state.xdcrItems?.labels}
                      horizontalAlign="right"
                      onSelect={({ selectedOption }) => {
                        vm.setState({
                          items: {
                            ...vm.state.items,
                            xdcr: selectedOption,
                          },
                        });
                      }}
                    />
                  </div>
                )}

              {vm.enabledItems?.['@eventing-'] &&
                statisticsNewCtl.state.eventingItems?.values?.length && (
                  <div className="row flex-wrap margin-left-1">
                    <strong className="margin-right-quarter">Eventing</strong>
                    <MnSelect
                      className="inline max-width-2"
                      value={
                        vm.state.items?.eventing ||
                        statisticsNewCtl.state.eventingItems?.values[0]
                      }
                      values={statisticsNewCtl.state.eventingItems?.values}
                      labels={statisticsNewCtl.state.eventingItems?.labels}
                      horizontalAlign="right"
                      onSelect={({ selectedOption }) => {
                        vm.setState({
                          items: {
                            ...vm.state.items,
                            eventing: selectedOption,
                          },
                        });
                      }}
                    />
                  </div>
                )}

              {vm.enabledItems?.['@fts-'] &&
                statisticsNewCtl.state.ftsItems?.values?.length && (
                  <div className="row flex-wrap margin-left-1">
                    <strong className="margin-right-quarter">
                      Search Indexes
                    </strong>
                    <MnSelect
                      className="inline max-width-2"
                      value={
                        vm.state.items?.fts ||
                        statisticsNewCtl.state.ftsItems?.values[0]
                      }
                      values={statisticsNewCtl.state.ftsItems?.values}
                      labels={statisticsNewCtl.state.ftsItems?.labels}
                      horizontalAlign="right"
                      onSelect={({ selectedOption }) => {
                        vm.setState({
                          items: {
                            ...vm.state.items,
                            fts: selectedOption,
                          },
                        });
                      }}
                    />
                  </div>
                )}
            </div>
          )}

          {!statisticsNewCtl.getSelectedScenario().preset && (
            <button
              className="light adder margin-right-half margin-left-1"
              onClick={(e) => {
                e.stopPropagation();
                statisticsNewCtl.openChartBuilderDialog(
                  group,
                  statisticsNewCtl.getSelectedScenario(),
                  vm
                );
              }}
              title="add chart"
            >
              <span className="icon fa-plus-circle"></span> Add a Chart
            </button>
          )}
        </div>

        {vm.isDetailsOpened(groupID) && (
          <div className="row charts">
            {group.charts.map((chartID) => {
              const chart = chartsById[chartID];
              return (
                <MnStatisticsChartsChart
                  key={chartID + Object.values(vm.state.items).join(',')}
                  chartID={chartID}
                  chart={chart}
                  group={group}
                  statisticsNewCtl={statisticsNewCtl}
                  mnStatsGroupsCtl={vm}
                  groupID={groupID}
                  chartsById={chartsById}
                  items={vm.state.items}
                  rbac={rbac}
                  onDeleteChart={vm.deleteChart}
                  onEditChart={vm.editChart}
                  onOpenDetailedChartDialog={vm.openDetailedChartDialog}
                  poolDefault={vm.props.poolDefault}
                />
              );
            })}
          </div>
        )}
      </div>
    );
  }
}

export { MnStatisticsChartsGroup };
