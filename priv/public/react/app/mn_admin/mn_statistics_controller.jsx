import { ModalContext } from '../uib/template/modal/window.and.backdrop';
import { MnLifeCycleHooksToStream } from "../mn.core.js";
import { MnSelect } from "../components/directives/mn_select/mn_select.jsx";
import { UIRouter }  from "mn.react.router";
import { MnMainSpinner } from "../components/directives/mn_main_spinner.jsx";
import { MnStatisticsScenarioComponent } from "./mn_statistics_scenario_controller.jsx";
import mnHelper from "../components/mn_helper.js";
import mnPoolDefault from '../components/mn_pool_default.js';
import mnStatisticsNewService from "./mn_statistics_service.js";
import mnUserRolesService from "../mn_admin/mn_user_roles_service.js";
import mnStoreService from "../components/mn_store_service.js";
import axios from "axios";
import {mnPoller} from "../components/mn_poll.js";
import mnTasksDetails from "../components/mn_tasks_details.js";
import mnGsiService from "./mn_gsi_service.js";
import {MnHelperReactService} from "../mn.helper.react.service.js";
import {takeUntil} from "rxjs/operators";
import {MnStatisticsResetDialog} from "./mn_statistics_reset_dialog.jsx";
import {MnStatisticsGroupDialog} from "./mn_statistics_group_dialog.jsx";
import { MnStatisticsChartsGroup } from "./mn_statistics_charts_group.jsx";
import { MnStatisticsChartBuilderComponent } from "./mn_statistics_chart_builder_controller.jsx";

class MnStatisticsNewComponent extends MnLifeCycleHooksToStream {
  static contextType = ModalContext;

  constructor(props) {
    super(props);
    this.state = {
      showBlocks: {
        "Server Resources": true
      },
      scenarioId: null,
      xdcrItems: null,
      ftsItems: null,
      indexItems: null,
      eventingItems: null,
      viewItems: null,
      scenarios: null,
      scenariosById: null,
      groupsById: null,
      chartsById: null,
      nodes: [],
    };
  }

  componentWillMount() {
    var vm = this;
    const {openModal} = this.context;
    const {permissions: rbac} = this.props;

    // vm.mnStatisticsNewScope = $scope;
  
    vm.onSelectScenario = onSelectScenario;
    vm.onSelectZoom = onSelectZoom;
  
    vm.bucket = UIRouter.globals.params.scenarioBucket;
    vm.zoom = UIRouter.globals.params.scenarioZoom;
    vm.node = UIRouter.globals.params.statsHostname;
    //selected scenario holder
    vm.openGroupDialog = openGroupDialog;
    //only new /range api can support "All Buckets" aggregation, hence we are checking atLeast70
    vm.selectedBucket = UIRouter.globals.params.scenarioBucket || (mnPoolDefault.export.getValue().compat.atLeast70 ? "All Buckets": UIRouter.globals.params.scenarioBucket);
    vm.bucketNames = mnPoolDefault.export.getValue().compat.atLeast70 ? [...this.props.permissions.bucketNames['.stats!read'] || [], "All Buckets"] : this.props.permissions.bucketNames['.stats!read'];
    vm.onBucketChange = onBucketChange;
    vm.onSelectNode = onSelectNode;
    vm.getSelectedScenario = getSelectedScenario;
  
    vm.openChartBuilderDialog = openChartBuilderDialog;
    vm.resetDashboardConfiguration = resetDashboardConfiguration;
    vm.mnAdminStatsPoller = mnStatisticsNewService.mnAdminStatsPoller;
  
    activate();
  
    function resetDashboardConfiguration() {
      return openModal({
        component: MnStatisticsResetDialog
      }).then(() => mnUserRolesService.resetDashboard())
        .then(() => {
          vm.setState({
            scenarioId: mnStoreService.store("scenarios").last().id
          });
          UIRouter.stateService.go("^.statistics", {
            scenario: mnStoreService.store("scenarios").last().id
          });
          MnHelperReactService.rootScopeEmitter.emit("scenariosChanged");
        }, () => {});
    }

    function openGroupDialog() {
      openModal({
        component: MnStatisticsGroupDialog,
        resolve: {
          scenarioId: mnHelper.wrapInFunction(vm.state.scenarioId)
        }
      }).then((group) => {
        //TODO: implement anchor scroll
        // $location.hash('group-' + group.id);
        // $anchorScroll();
      }, () => {});
    }
  
  
    function openChartBuilderDialog(group, scenario, groupCtl) {
      openModal({
        component: MnStatisticsChartBuilderComponent,
        props: {
          poolDefault: mnPoolDefault.export.getValue()
        },
        resolve: {
          scenario: mnHelper.wrapInFunction(scenario),
          chart: mnHelper.wrapInFunction(),
          group: mnHelper.wrapInFunction(group)
        }
      }).then(() => {
        mnUserRolesService.saveDashboard();
        groupCtl.maybeShowItemsControls();
      }, () => {});
    }
  
    function onSelectNode({selectedOption}) {
      UIRouter.stateService.go('^.statistics', {
        statsHostname: selectedOption.indexOf("All Server Nodes") > -1 ? "all" : selectedOption
      });
    }
  
    function onBucketChange({selectedOption}) {
      UIRouter.stateService.go('^.statistics', {
        scenarioBucket: selectedOption.indexOf("All Buckets") > -1 ? null : selectedOption,
        commonScope: null,
        commonCollection: null
      }, {reload: true});
    }
  
    function onSelectScenario(scenarioId) {
      UIRouter.stateService.go('^.statistics', {
        scenario: scenarioId,
      });
    }
  
    function onSelectZoom({selectedOption}) {
      UIRouter.stateService.go('^.statistics', {
        scenarioZoom: selectedOption
      });
    }
  
    function initItemsDropdownSelect() {
      if (rbac.cluster.tasks.read) {
        new mnPoller(vm, function () {
          return mnTasksDetails.get().then(function (rv) {
            if (!UIRouter.globals.params.scenarioBucket) {
              return;
            }
            return rv.tasksXDCR.filter(function (row) {
              return row.source == UIRouter.globals.params.scenarioBucket;
            });
          });
        })
          .setInterval(10000)
          .subscribe(xdcrItems => {
            vm.setState({
              xdcrItems: (xdcrItems || []).reduce((acc, xdcrItem) => {
                acc.values.push('replications/' + xdcrItem.id + '/');
                acc.labels.push(xdcrItem.source + '->' + xdcrItem.target.split('buckets/')[1]);
                return acc;
              }, {values: [], labels: []})
            });
          })
          .reloadOnScopeEvent("reloadXdcrPoller")
          .cycle();
      }
  
      if (rbac.cluster.settings.fts && rbac.cluster.settings.fts.read) {
        new mnPoller(vm, function () {
          return axios.get('/_p/fts/api/index').then(function(rv) {
            return Object.keys(rv.data.indexDefs.indexDefs).reduce(function (acc, key) {
              var index = rv.data.indexDefs.indexDefs[key];
              if (index.sourceName == UIRouter.globals.params.scenarioBucket) {
                acc.push(index);
              }
              return acc;
            }, []);
          });
        })
          .setInterval(10000)
          .subscribe(ftsItems => {
            vm.setState({
              ftsItems: (ftsItems || []).reduce((acc, ftsItem) => {
                acc.values.push('fts/' + ftsItem.name + '/');
                acc.labels.push(ftsItem.name);
                return acc;
              }, {values: [], labels: []})
            });
          })
          .reloadOnScopeEvent("reloadXdcrPoller")
          .cycle();
      }
  
      if (rbac.cluster.collection['.:.:.'].n1ql.index.read) {
        new mnPoller(vm, function () {
          return mnGsiService.getIndexStatus().then(function (rv) {
            if (!UIRouter.globals.params.scenarioBucket) {
              return;
            }
            return rv.indexes.filter(index => index.bucket === UIRouter.globals.params.scenarioBucket);
          });
        })
          .setInterval(10000)
          .subscribe(indexes => {
            vm.setState({
              indexItems: (indexes || []).reduce((acc, indexItem) => {
                acc.values.push('index/' + indexItem.index + '/');
                acc.labels.push(indexItem.index);
                return acc;
              }, {values: [], labels: []})
            });
          })
          .reloadOnScopeEvent("indexStatusURIChanged")
          .cycle();
      }
  
      if (rbac.cluster.eventing.functions.manage) {
        new mnPoller(vm, function () {
          return axios.get('/_p/event/api/v1/status');
        })
          .setInterval(10000)
          .subscribe(resp => {
            vm.setState({
              eventingItems: ((resp.data && resp.data.apps) || []).reduce((acc, func) => {
                if (func.composite_status == "deployed") {
                  let funcName = '';
                  if (func.function_scope && func.function_scope.bucket !== '*') {
                   funcName = `${func.function_scope.bucket}/${func.function_scope.scope}/`;
                  }
                  funcName += func.name;
                  acc.values.push(funcName);
                }
                return acc;
              }, {values: []})
            });
          })
          .cycle();
      }
  
      if (rbac.cluster.bucket['.'].views.read && UIRouter.globals.params.scenarioBucket) {
        new mnPoller(vm, function () {
          return mnStatisticsNewService.getStatsDirectory(UIRouter.globals.params.scenarioBucket, {})
            .then(function (rv) {
              if (!UIRouter.globals.params.scenarioBucket) {
                return;
              }
              return rv.data.blocks.filter(function (block) {
                if (block.blockName.includes("View Stats")) {
                  block.statId = block.blockName.split(": ")[1];
                  var name = block.stats[0].name.split("/");
                  name.pop()
                  block.statKeyPrefix = name.join("/") + "/";
                  return true;
                }
                return false;
              });
            });
        })
          .setInterval(10000)
          .subscribe(views => {
            vm.setState({
              viewItems: (views || []).reduce((acc, viewItem) => {
                acc.values.push(viewItem.statKeyPrefix);
                acc.labels.push(viewItem.statId);
                return acc;
              }, {values: [], labels: []})
            });
          })
          .reloadOnScopeEvent("reloadViewsPoller")
          .cycle();
      }
    }
  
    function getSelectedScenario() {
      return vm.state.scenariosById && vm.state.scenariosById[vm.state.scenarioId] || {};
    }
  
    function groupById(arr) {
      return arr.reduce((acc, item) => {
        acc[item.id] = item;
        return acc;
      }, {});
    }
  
    function activate() {
      initItemsDropdownSelect();
  
      vm.mnAdminStatsPoller.heartbeat
        .setInterval(mnStatisticsNewService.defaultZoomInterval(vm.zoom));
  
      if (rbac.cluster.collection['.:.:.'].stats.read) {
        vm.setState({scenarioId: UIRouter.globals.params.scenario});
        
        //Update of scenarios, groups and charts happens in getUserProfile
        new mnPoller(vm, function () {
          return mnUserRolesService.getUserProfile();
        })
          .setInterval(10000)
          .reloadOnScopeEvent("scenariosChanged")
          .cycle();

        mnStoreService.store("scenarios").shareSubject()
          .pipe(takeUntil(vm.mnOnDestroy))
          .subscribe(scenarios => {
            vm.setState({
              scenariosById: groupById(scenarios),
              scenarios
            });
          });
        mnStoreService.store("groups").shareSubject()
          .pipe(takeUntil(vm.mnOnDestroy))
          .subscribe(groups => {
            vm.setState({groupsById: groupById(groups)});
          });
        mnStoreService.store("charts").shareSubject()
          .pipe(takeUntil(vm.mnOnDestroy))
          .subscribe(charts => {
            vm.setState({chartsById: groupById(charts)});
          });
      }
  
      new mnPoller(vm, function () {
        return mnStatisticsNewService.prepareNodesList(UIRouter.globals.params);
      })
        .subscribe("nodes", vm)
        .reloadOnScopeEvent("nodesChanged")
        .cycle();
    }
  }

  render() {
    const vm = this;
    const {permissions: rbac, poolDefault} = this.props;
    const {scenarios, nodes,scenariosById, groupsById, chartsById} = vm.state;

    if (!rbac.cluster.collection['.:.:.'].stats.read) {
      return (
        <div>
          <img src="../cb_logo_bug_white_2.svg" 
               className="filter-gray" 
               style={{margin: '0 auto', width: '40%', display: 'block'}}/>
        </div>
      );
    }


    if (rbac.cluster.collection['.:.:.'].stats.read && !scenarios) {
      return (
        <div>
          <h1>Loading...</h1>
        </div>
      );
      // TODO:
      // return (
      //   <MnMainSpinner 
      //     value={rbac.cluster.collection['.:.:.'].stats.read && !vm.scenarios}/>
      // );
    }

    const selectedScenario = vm.getSelectedScenario();
    const hasGroups = selectedScenario?.groups?.length > 0;

    return (
      <>
        <div style={{display: rbac.cluster.collection['.:.:.'].stats.read ? 'block' : 'none'}}>
          <div className="row margin-bottom-1-5">
            <div className="row flex-left flex-wrap">
              <span>
                <h5>Choose Dashboard &nbsp;<small>or create your own</small></h5>
                <div className="margin-right-half">
                  <MnStatisticsScenarioComponent
                    statisticsNewCtl={vm}
                    rbac={rbac} />
                </div>
              </span>

              <span>
                <h5>Stat Interval</h5>
                <MnSelect
                  className="inline fix-width-1-5 margin-right-half"
                  value={vm.zoom}
                  values={['minute', 'hour', 'day', 'week', 'month']}
                  onSelect={vm.onSelectZoom}
                  capitalize={true}/>
              </span>

              <span>
                <h5>Bucket</h5>
                <MnSelect
                  className="inline margin-right-half"
                  value={vm.selectedBucket}
                  values={vm.bucketNames || []}
                  hasSearch={true}
                  onSelect={vm.onBucketChange}/>
              </span>

              <span>
                <h5>Nodes</h5>
                <MnSelect
                  value={nodes.nodesNames?.selected}
                  values={nodes.nodesNames || []}
                  hasSearch={true}
                  onSelect={vm.onSelectNode}/>
              </span>
            </div>

            <div className="row flex-right flex-wrap resp-hide-sml">
              <button
                onClick={vm.resetDashboardConfiguration}
                className="light dashboard-delete"
                title="reset & delete customizations">
                <span className="icon fa-trash"></span> Reset
              </button>
              <button
                disabled={!scenarios.length}
                onClick={vm.openGroupDialog}
                className="light adder"
                style={{display: vm.getSelectedScenario().preset ? 'none' : 'block'}}
                title="add chart group">
                <span className="icon fa-plus-circle"></span> Add Group
              </button>
            </div>
          </div>

          <div className="width-12 margin-bottom-4">
            {!hasGroups ? (
              <div className="zero-content">
                No charts to display yet.
                <a onClick={vm.openGroupDialog}>Add a Group</a> to start, then add charts.<br/>
                NOTE: All your changes will be auto-saved.
              </div>
            ) : (
              selectedScenario.groups.map((groupID) => {
                const group = groupsById[groupID];
                if (!group) return null;

                const shouldShowGroup = 
                  poolDefault.compat.atLeast70 || vm.selectedBucket;
                
                if (!shouldShowGroup) return null;

                const isEnterpriseValid = 
                  group.enterprise === undefined || poolDefault.isEnterprise;

                if (!isEnterpriseValid) return null;

                return (
                  <MnStatisticsChartsGroup
                    key={groupID}
                    group={group}
                    groupID={groupID}
                    rbac={rbac}
                    poolDefault={poolDefault}
                    statisticsNewCtl={vm}
                    chartsById={chartsById}
                  />
                );
              })
            )}
          </div>
        </div>
      </>
    );
  }
}

export {MnStatisticsNewComponent};