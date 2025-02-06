import { MnLifeCycleHooksToStream } from '../mn.core.js';
import _ from 'lodash';
import { MnSelect } from '../components/directives/mn_select/mn_select.jsx';
import mnStatisticsNewService from './mn_statistics_service.js';
import mnStatisticsDescriptionService from './mn_statistics_description_service.js';
import mnStoreService from '../components/mn_store_service.js';
import mnUserRolesService from './mn_user_roles_service.js';
import { UIRouter } from '../mn.react.router.js';
import { MnFormatServices } from '../mn.pipes.js';
import { MnHelperReactService } from '../mn.helper.react.service.js';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';

function mnFormatStatsSectionsFilter(section) {
  if (section.includes('@')) {
    section = section.substr(1);
  }

  if (section.includes('-')) {
    section = section.substr(0, section.length - 1);
  }

  switch (section) {
    case 'items':
      return 'Item';
    case 'system':
      return 'System';
    case 'xdcr':
      return 'XDCR';
    default:
      return section;
  }
}

class MnStatisticsChartBuilderComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    //poolDefault, chart, group, scenario, $uibModalInstance, $state, mnFormatStatsSectionsFilter, mnFormatServicesFilter
    this.state = {
      tab: null,
      newChart: {
        stats: {},
        size: 'small',
        specificStat: 'true',
      },
      selectedGroup: null,
      selectedKVFilters: {},
      disableStats: false,
      viewLoading: false,
    };
  }

  componentWillMount() {
    var vm = this;
    vm.isEditing = !!this.props.chart;
    vm.create = create;
    const mnFormatServicesFilter = MnFormatServices.transform;
    vm.mnFormatServicesFilter = mnFormatServicesFilter;

    vm.units = {};
    vm.breadcrumbs = {};
    vm.showInPopup = false;
    vm.tabs = [
      '@system',
      '@kv',
      '@index',
      '@query',
      '@fts',
      '@cbas',
      '@eventing',
      '@xdcr',
    ];
    const { chart, group, scenario } = this.props;

    vm.statIsNotSupported = [];
    vm.onStatChecked = onStatChecked;
    vm.onSpecificChecked = onSpecificChecked;
    vm.maybeDisableField = maybeDisableField;
    vm.filterStats = filterStats;
    vm.selectTab = selectTab;
    vm.statsDesc = mnStatisticsDescriptionService.getStats();

    vm.kvGroups = mnStatisticsDescriptionService.getKvGroups();
    vm.getSelectedStats = getSelectedStats;
    vm.getSelectedStatsLength = getSelectedStatsLength;
    vm.formatGroupLabel = formatGroupLabel;
    vm.filterGroupName = filterGroupName;

    var selectedByNodeStats = {};
    var selectedStats = {};

    activate();

    function formatGroupLabel(service) {
      switch (service) {
        case '@index':
          return 'Indexes';
        case '@xdcr':
          return 'Replications';
        case '@kv':
          return 'Views';
        default:
          return 'Items';
      }
    }

    function selectTab(name) {
      vm.setState({ tab: name });
    }

    function getSelectedStatsLength() {
      return Object.keys(getSelectedStats()).length;
    }

    function getSelectedStats() {
      return Object.keys(vm.state.newChart.stats).reduce(function (acc, key) {
        if (vm.state.newChart.stats[key]) {
          acc[key] = vm.state.newChart.stats[key];
        }
        return acc;
      }, {});
    }

    function reActivateStats() {
      vm.units = {};
      vm.breadcrumbs = {};
      vm.setState({ disableStats: false });

      Object.keys(getSelectedStats()).forEach((descPath) =>
        onStatChecked(descPath, true)
      );
    }

    function filterStats(section) {
      return !section.includes('-');
    }

    function maybeDisableField(descPath) {
      var stat = mnStatisticsNewService.readByPath(descPath);
      return (
        (vm.state.newChart.specificStat == 'false' &&
          vm.state.disableStats &&
          !vm.units[stat.unit]) ||
        (vm.state.newChart.specificStat == 'true' &&
          vm.state.disableStats &&
          !vm.state.newChart.stats[descPath])
      );
    }

    function onSpecificChecked(value) {
      if (value == 'true') {
        selectedStats = Object.assign({}, vm.state.newChart.stats);
        vm.setState((state) => ({
          newChart: {
            ...state.newChart,
            specificStat: 'true',
            stats: selectedByNodeStats,
          },
        }));
      } else {
        selectedByNodeStats = Object.assign({}, vm.state.newChart.stats);
        vm.setState((state) => ({
          newChart: {
            ...state.newChart,
            specificStat: 'false',
            stats: selectedStats,
          },
        }));
      }

      setTimeout(() => reActivateStats(), 0);
    }

    function onStatChecked(descPath, value) {
      var desc = mnStatisticsNewService.readByPath(descPath);
      var breadcrumb = descPath.split('.');
      if (!desc) {
        vm.setState((state) => ({
          newChart: {
            ...state.newChart,
            stats: { ...state.newChart.stats, [descPath]: false },
          },
        }));
        vm.statIsNotSupported.push(breadcrumb.pop());
        return;
      }

      if (vm.units[desc.unit] === undefined) {
        vm.units[desc.unit] = 0;
      }

      if (value) {
        vm.units[desc.unit] += 1;
        vm.breadcrumbs[
          breadcrumb
            .map(mnFormatStatsSectionsFilter)
            .map(mnFormatServicesFilter)
            .join(' > ')
        ] = true;
      } else {
        vm.units[desc.unit] -= 1;
        delete vm.breadcrumbs[
          breadcrumb
            .map(mnFormatStatsSectionsFilter)
            .map(mnFormatServicesFilter)
            .join(' > ')
        ];
      }

      var selectedUnitsCount = Object.keys(vm.units).reduce(function (
        acc,
        key
      ) {
        if (vm.units[key] > 0) {
          acc += 1;
        }
        return acc;
      }, 0);

      vm.setState((state) => ({
        disableStats:
          vm.state.newChart.specificStat !== 'false'
            ? selectedUnitsCount >= 1
            : selectedUnitsCount >= 2,
        newChart: {
          ...state.newChart,
          stats: { ...state.newChart.stats, [descPath]: value },
        },
      }));
    }

    function activate() {
      if (vm.isEditing) {
        const newChart = _.cloneDeep(chart);
        newChart.specificStat = newChart.specificStat.toString();
        const selectedGroup = group.id;
        vm.groups = scenario.groups.map(function (id) {
          return mnStoreService.store('groups').get(id);
        });
        vm.groupIds = vm.groups.map((group) => group.id);
        vm.setState({
          newChart,
          selectedGroup,
        });
        Object.keys(newChart.stats).forEach((descPath) =>
          onStatChecked(descPath, true)
        );
      } else {
        vm.setState({
          newChart: {
            stats: {},
            size: 'small',
            specificStat: 'true',
          },
        });
      }

      vm.bucket = UIRouter.globals.params.scenarioBucket;

      if (vm.isEditing) {
        vm.setState({
          tab: Object.keys(chart.stats)
            .map(function (stat) {
              var tab = stat.split('.')[0];
              if (tab.includes('-')) {
                tab = tab.substr(0, tab.length - 1);
              }
              return tab;
            })
            .sort(function (a, b) {
              return vm.tabs.indexOf(a) - vm.tabs.indexOf(b);
            })[0],
        });

        vm.setState({
          selectedKVFilters: Object.keys(chart.stats)
            .filter(function (stat) {
              return stat.includes('@kv') && !stat.includes('@items');
            })
            .reduce(function (acc, kvStat) {
              Object.keys(vm.kvGroups).forEach(function (kvFilter) {
                if (vm.kvGroups[kvFilter].includes(kvStat.split('.')[1])) {
                  acc[kvFilter] = true;
                }
              });
              return acc;
            }, {}),
        });
      } else {
        vm.setState({
          tab: vm.tabs[0],
        });
      }
    }

    function create() {
      var chart = {
        size: vm.state.newChart.size,
        specificStat: vm.state.newChart.specificStat === 'true',
        id: vm.state.newChart.id,
        stats: getSelectedStats(),
      };
      var toGroup = mnStoreService
        .store('groups')
        .get(vm.state.selectedGroup || group.id);
      var fromGroup;
      if (vm.isEditing) {
        if (group.id !== vm.state.selectedGroup) {
          fromGroup = mnStoreService.store('groups').get(group.id);
          fromGroup.charts.splice(fromGroup.charts.indexOf(chart.id), 1);
          toGroup.charts.push(chart.id);
        }
        mnStoreService.store('charts').put(chart);
      } else {
        toGroup.charts.push(mnStoreService.store('charts').add(chart).id);
      }
      mnUserRolesService.saveDashboard().then(() => {
        MnHelperReactService.rootScopeEmitter.emit('scenariosChanged');
        vm.props.onClose();
      });
    }

    function filterGroupName(groupId) {
      return vm.groups.find((group) => groupId === group.id).name;
    }
  }

  render() {
    const vm = this;
    const breadcrumbs = vm.breadcrumbs;
    const { tab, newChart, selectedKVFilters, viewLoading, selectedGroup } =
      vm.state;

    return (
      <div className="chart-builder dialog-xlg">
        <div className="panel-header">
          <h2>{vm.isEditing ? 'Edit' : 'Add'} Chart</h2>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            vm.create();
          }}
        >
          {viewLoading && <div className="spinner" />}

          <div className="panel-content" style={{ paddingBottom: 0 }}>
            <div className="row items-top content-box min-padding margin-bottom-half">
              <div className="column">
                <h5>Multi-Stat or Multi-Node Chart?</h5>
                <div className="checkbox-list" style={{ marginTop: '4px' }}>
                  <input
                    type="radio"
                    id="for-individual-nodes"
                    checked={newChart.specificStat === 'true'}
                    onChange={(e) => vm.onSpecificChecked(e.target.value)}
                    name="specificStat"
                    value="true"
                  />
                  <label htmlFor="for-individual-nodes">
                    show separate nodes + single statistic
                  </label>

                  <input
                    type="radio"
                    id="for-whole-cluster"
                    checked={newChart.specificStat === 'false'}
                    onChange={(e) => vm.onSpecificChecked(e.target.value)}
                    name="specificStat"
                    value="false"
                  />
                  <label htmlFor="for-whole-cluster">
                    combine node data + multiple stats per chart
                  </label>
                </div>
              </div>

              <div className="margin-right-1 nowrap">
                <h5>Chart Size</h5>
                <MnSelect
                  className="fix-width-half"
                  value={newChart.size}
                  onSelect={({ selectedOption }) =>
                    vm.setState((state) => ({
                      newChart: { ...state.newChart, size: selectedOption },
                    }))
                  }
                  values={['small', 'medium', 'large']}
                  labels={['S', 'M', 'L']}
                />
              </div>

              {vm.isEditing && (
                <div className="nowrap">
                  <h5>Group</h5>
                  <MnSelect
                    className="inline"
                    mnDisabled={!vm.isEditing}
                    value={selectedGroup}
                    onSelect={({ selectedOption }) =>
                      vm.setState({ selectedGroup: selectedOption })
                    }
                    values={vm.groupIds}
                    valuesMapping={vm.filterGroupName}
                  />
                </div>
              )}
            </div>

            <div className="row pills margin-bottom-half">
              {vm.tabs.map(
                (name) =>
                  ((name !== '@eventing' && name !== '@cbas') ||
                    vm.props.poolDefault.isEnterprise) && (
                    <a
                      key={name}
                      className={`margin-right-half ${tab === name ? 'selected' : ''}`}
                      onClick={() => vm.selectTab(name)}
                    >
                      {vm.mnFormatServicesFilter(
                        mnFormatStatsSectionsFilter(name)
                      )}
                    </a>
                  )
              )}
            </div>

            {tab === '@kv' && (
              <div className="row margin-bottom-half">
                {Object.entries(vm.kvGroups).map(([name, _]) => (
                  <div
                    key={name}
                    className={`checkbox-filter ${selectedKVFilters[name] ? 'selected' : ''}`}
                  >
                    <input
                      id={`kv-filter-${tab}.${name}`}
                      type="checkbox"
                      checked={selectedKVFilters[name] || false}
                      onChange={(e) => {
                        const newFilters = { ...selectedKVFilters };
                        newFilters[name] = e.target.checked;
                        vm.setState({ selectedKVFilters: newFilters });
                      }}
                    />
                    <label
                      htmlFor={`kv-filter-${tab}.${name}`}
                      className="initialcaps"
                    >
                      {name}
                    </label>
                  </div>
                ))}
              </div>
            )}

            <div className="scrolling-wrapper">
              <div className="margin-bottom-1-5 margin-right-half columns-3">
                {/* KV Stats */}
                {tab === '@kv' && (
                  <div>
                    {Object.entries(vm.kvGroups).map(([name1, group]) => (
                      <div key={name1}>
                        {group.map((name) => {
                          const isDisabled = vm.maybeDisableField(
                            '@kv-.' + name
                          );
                          const hasDesc = vm.statsDesc['@kv-'][name]?.desc;
                          if (!selectedKVFilters[name1] || !hasDesc)
                            return null;

                          return (
                            <div
                              key={name}
                              style={{ opacity: isDisabled ? 0.3 : 1 }}
                            >
                              <input
                                id={`stat-@kv-.${name}-checkbox`}
                                type="checkbox"
                                checked={
                                  newChart.stats['@kv-.' + name] || false
                                }
                                onChange={(e) =>
                                  vm.onStatChecked(
                                    '@kv-.' + name,
                                    e.target.checked
                                  )
                                }
                                disabled={isDisabled}
                              />
                              <OverlayTrigger
                                placement="auto-end"
                                delay={{ show: 500, hide: 0 }}
                                overlay={
                                  <Tooltip id={`tooltip-kv-${name}`}>
                                    {vm.statsDesc['@kv-'][name].desc}
                                  </Tooltip>
                                }
                              >
                                <label htmlFor={`stat-@kv-.${name}-checkbox`}>
                                  {vm.statsDesc['@kv-'][name].title}
                                </label>
                              </OverlayTrigger>
                            </div>
                          );
                        })}
                      </div>
                    ))}
                  </div>
                )}

                {/* XDCR/VIEWS/INDEXES Stats */}
                {vm.statsDesc[tab + '-']?.['@items'] &&
                  Object.entries(vm.statsDesc[tab + '-']['@items']).map(
                    ([name, stat]) => {
                      if (!stat.desc) return null;
                      const statPath = `${tab}-.@items.${name}`;
                      const isDisabled = vm.maybeDisableField(statPath);

                      return (
                        <div
                          key={name}
                          style={{ opacity: isDisabled ? 0.3 : 1 }}
                        >
                          <input
                            id={`stat-${statPath}-checkbox`}
                            type="checkbox"
                            checked={newChart.stats[statPath] || false}
                            onChange={(e) =>
                              vm.onStatChecked(statPath, e.target.checked)
                            }
                            disabled={isDisabled}
                          />
                          <OverlayTrigger
                            placement="auto-end"
                            delay={{ show: 500, hide: 0 }}
                            overlay={
                              <Tooltip id={`tooltip-items-${name}`}>
                                {stat.desc}
                              </Tooltip>
                            }
                          >
                            <label htmlFor={`stat-${statPath}-checkbox`}>
                              {stat.title} (per item)
                            </label>
                          </OverlayTrigger>
                        </div>
                      );
                    }
                  )}

                {/* Non-KV Stats */}
                {vm.statsDesc[tab] &&
                  tab !== '@kv' &&
                  Object.entries(vm.statsDesc[tab]).map(([name, stat]) => {
                    if (!stat.desc || name === '@items') return null;
                    const statPath = `${tab}.${name}`;
                    const isDisabled = vm.maybeDisableField(statPath);

                    return (
                      <div key={name} style={{ opacity: isDisabled ? 0.3 : 1 }}>
                        <input
                          id={`stat-${statPath}-checkbox`}
                          type="checkbox"
                          checked={newChart.stats[statPath] || false}
                          onChange={(e) =>
                            vm.onStatChecked(statPath, e.target.checked)
                          }
                          disabled={isDisabled}
                        />
                        <OverlayTrigger
                          placement="auto-end"
                          delay={{ show: 500, hide: 0 }}
                          overlay={
                            <Tooltip id={`tooltip-${name}`}>
                              {stat.desc}
                            </Tooltip>
                          }
                        >
                          <label htmlFor={`stat-${statPath}-checkbox`}>
                            {stat.title}
                          </label>
                        </OverlayTrigger>
                      </div>
                    );
                  })}

                {/* Service Specific Stats */}
                {vm.statsDesc[tab + '-'] &&
                  tab !== '@kv' &&
                  Object.entries(vm.statsDesc[tab + '-']).map(
                    ([name, stat]) => {
                      if (!stat || name === '@items') return null;
                      const statPath = `${tab}-.${name}`;
                      const isDisabled = vm.maybeDisableField(statPath);

                      return (
                        <div
                          key={name}
                          style={{ opacity: isDisabled ? 0.3 : 1 }}
                        >
                          <input
                            id={`stat-${statPath}-checkbox`}
                            type="checkbox"
                            checked={newChart.stats[statPath] || false}
                            onChange={(e) =>
                              vm.onStatChecked(statPath, e.target.checked)
                            }
                            disabled={isDisabled}
                          />
                          <OverlayTrigger
                            placement="auto-end"
                            delay={{ show: 500, hide: 0 }}
                            overlay={
                              <Tooltip id={`tooltip-specific-${name}`}>
                                {stat.desc}
                              </Tooltip>
                            }
                          >
                            <label htmlFor={`stat-${statPath}-checkbox`}>
                              {stat.title}
                            </label>
                          </OverlayTrigger>
                        </div>
                      );
                    }
                  )}
              </div>
            </div>
          </div>

          <div className="panel-footer spaced scroll-shadow">
            <div className="text-smaller flex-grow-2 margin-right-15">
              {Object.keys(breadcrumbs).map((breadcrumb) => (
                <span key={breadcrumb} className="cb-breadcrumb">
                  {breadcrumb}
                  <span className="breadcrumb-divider"> | </span>
                </span>
              ))}
            </div>
            <div className="row row-min">
              <a className="text-nowrap" onClick={vm.props.onDismiss}>
                Cancel
              </a>
              <button type="submit" disabled={!vm.getSelectedStatsLength()}>
                Save Chart
              </button>
            </div>
          </div>
        </form>
      </div>
    );
  }
}

export { MnStatisticsChartBuilderComponent };
