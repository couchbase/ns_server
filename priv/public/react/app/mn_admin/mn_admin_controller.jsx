import React from 'react';
import { fromEvent, timer } from 'rxjs';
import { tap, switchMap, takeUntil } from 'rxjs/operators';
import { MnElementDepot } from '../mn.element.crane';
import { UIView } from '@uirouter/react';
import { ModalProvider } from '../uib/template/modal/window.and.backdrop';
import { MnLifeCycleHooksToStream, dayjs } from 'mn.core';
import mnAlertsService from '../components/mn_alerts';
import { mnEtagPoller, mnPoller } from '../components/mn_poll';
import { MnAdminService } from '../mn.admin.service';
import { MnHelperReactService } from '../mn.helper.react.service';
import mnPoolDefault from '../components/mn_pool_default';
import mnBucketsService from './mn_buckets_service.js';
import mnPermissions from '../components/mn_permissions.js';
// import { MnSpinner } from '../components/directives/mn_spinner.jsx';
import mnSettingsClusterService from './mn_settings_cluster_service.js';
import mnTasksDetails from '../components/mn_tasks_details.js';
import mnHelper from '../components/mn_helper.js';
import _ from 'lodash';
import { MnFormatProgressMessage } from '../mn.pipes.js';
import mnAuthService from '../mn_auth/mn_auth_service.js';
import mnPools from '../components/mn_pools.js';
import { UIRouter } from 'mn.react.router';
import mnSettingsAutoFailoverService from './mn_settings_auto_failover_service.js';
import mnPromiseHelper from '../components/mn_promise_helper.js';
import mnLostConnectionService from './mn_lost_connection_service.js';
import { MnSessionService } from '../mn.session.service.js';
import mnUserRolesService from './mn_user_roles_service.js';
import { Dropdown, Tooltip, OverlayTrigger } from 'react-bootstrap';
import { UISref, UISrefActive } from '@uirouter/react';
import MnDragAndDrop from '../components/directives/mn_drag_and_drop.jsx';
import { mnMsToTime, decodeCompatVersion } from '../components/mn_filters.js';

function formatFailoverWarnings(warning) {
  switch (warning) {
    case 'rebalanceNeeded':
      return 'Rebalance required, some data is not currently replicated.';
    case 'hardNodesNeeded':
      return 'At least two servers with the data service are required to provide replication.';
    case 'softNodesNeeded':
      return 'Additional active servers or server groups required to provide the desired number of replicas.';
    case 'softRebalanceNeeded':
      return 'Rebalance recommended, some data does not have the desired replicas configuration.';
    case 'unbalancedServerGroups':
      return 'Server groups are unbalanced; this may result in uneven load distrubution.';
    default:
      return warning;
  }
}

class MnAdminComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      alerts: [],
      tasks: [],
      mainSpinnerCounter: 0,
      rbac: null,
      poolDefault: null,
      lostConnState: null,
      autoFailoverSettings: null,
      moxiBucket: null,
      isProgressBarClosed: true,
      clientAlerts: {
        rebalanceDataLoading: false,
        moxiBucket: false,
        hideCompatibility: false,
        maxCount: false,
        ceNodesLimit: false,
      },
    };
  }
  componentWillMount() {
    const vm = this;
    const { pools, poolDefault, whoami } = vm.props;

    vm.launchpadId = pools.launchID;
    vm.implementationVersion = pools.implementationVersion;
    vm.logout = mnAuthService.logout;
    vm.resetAutoFailOverCount = resetAutoFailOverCount;
    vm.toggleProgressBar = toggleProgressBar;
    vm.filterTasks = filterTasks;
    vm.showResetPasswordDialog = showResetPasswordDialog;
    vm.postCancelRebalanceRetry = postCancelRebalanceRetry;
    vm.showClusterInfoDialog = showClusterInfoDialog;
    vm.isDeveloperPreview = pools.isDeveloperPreview;
    vm.mainSpinnerCounter = mnHelper.mainSpinnerCounter;
    vm.majorMinorVersion = pools.implementationVersion
      .split('.')
      .splice(0, 2)
      .join('.');

    //TODO: get back to this
    // $rootScope.mnGlobalSpinnerFlag = false;

    vm.user = whoami;

    vm.enableInternalSettings = UIRouter.globals.params.enableInternalSettings;
    vm.enableDeveloperSettings =
      UIRouter.globals.params.enableDeveloperSettings;
    vm.runInternalSettingsDialog = runInternalSettingsDialog;
    vm.runDeveloperSettingsDialog = runDeveloperSettingsDialog;
    vm.lostConnState = mnLostConnectionService.export;
    MnHelperReactService.async(vm, 'lostConnState');

    vm.clientAlerts = mnAlertsService.clientAlerts;
    MnHelperReactService.async(vm, 'clientAlerts');

    vm.alerts = mnAlertsService.alerts;
    MnHelperReactService.async(vm, 'alerts');
    vm.closeAlert = mnAlertsService.removeItem;
    vm.setHideNavSidebar = mnPoolDefault.setHideNavSidebar;
    vm.postStopRebalance = postStopRebalance;
    vm.closeCustomAlert = closeCustomAlert;
    vm.enableCustomAlert = enableCustomAlert;

    vm.getRebalanceReport = getRebalanceReport;

    vm.rbac = mnPermissions.export;
    MnHelperReactService.async(vm, 'rbac');
    vm.poolDefault = mnPoolDefault.export;
    MnHelperReactService.async(vm, 'poolDefault');
    vm.pools = mnPools.export;
    MnHelperReactService.async(vm, 'pools');
    vm.buckets = mnBucketsService.export;
    MnHelperReactService.async(vm, 'buckets');

    function disableHoverEventDuringScroll() {
      let bodyElement = document.querySelector('body');

      fromEvent(bodyElement, 'scroll')
        .pipe(
          tap(() => bodyElement.classList.add('mn-scroll-active')),
          switchMap(() => timer(200)),
          takeUntil(vm.mnOnDestroy)
        )
        .subscribe(() => bodyElement.classList.remove('mn-scroll-active'));
    }

    disableHoverEventDuringScroll();

    activate();

    function closeCustomAlert(alertName) {
      vm.clientAlerts.next({
        ...vm.clientAlerts.getValue(),
        [alertName]: true,
      });
    }

    function enableCustomAlert(alertName) {
      vm.clientAlerts.next({
        ...vm.clientAlerts.getValue(),
        [alertName]: false,
      });
    }

    function postCancelRebalanceRetry(id) {
      mnSettingsClusterService.postCancelRebalanceRetry(id);
    }

    async function showClusterInfoDialog() {
      // TODO: get back to this
      // await import('./mn_logs_service.js');
      // await $ocLazyLoad.load({ name: 'mnLogsService' });
      // var mnLogsService = $injector.get('mnLogsService');
      // mnLogsService.showClusterInfoDialog();
    }

    async function showResetPasswordDialog() {
      // TODO: get back to this
      // vm.showUserDropdownMenu = false;
      // await import('./mn_reset_password_dialog_controller.js');
      // await $ocLazyLoad.load({ name: 'mnResetPasswordDialog' });
      // var mnResetPasswordDialogService = $injector.get(
      //   'mnResetPasswordDialogService'
      // );
      // mnResetPasswordDialogService.showDialog(whoami);
    }

    async function postStopRebalance() {
      // TODO: get back to this
      // await import('./mn_servers_service.js');
      // await $ocLazyLoad.load({ name: 'mnServersService' });
      // var mnServersService = $injector.get('mnServersService');
      // return mnPromiseHelper(
      //   vm,
      //   mnServersService.stopRebalanceWithConfirm()
      // ).broadcast('reloadServersPoller');
    }

    function runDeveloperSettingsDialog() {
      // TODO: get back to this
      // import('./mn_developer_settings_controller.js').then(function () {
      //   $ocLazyLoad.load({ name: 'mnDeveloperSettings' });
      //   $uibModal.open({
      //     template: mnDeveloperSettingsTemplate,
      //     controller: 'mnDeveloperSettingsController as devSettingsCtl',
      //   });
      // });
    }

    function runInternalSettingsDialog() {
      // TODO: get back to this
      // import('./mn_internal_settings_controller.js').then(function () {
      //   $ocLazyLoad.load({ name: 'mnInternalSettings' });
      //   $uibModal.open({
      //     template: mnInternalSettingsTemplate,
      //     controller: 'mnInternalSettingsController as internalSettingsCtl',
      //   });
      // });
    }

    async function loadAndRunPoorMansAlertsDialog(
      $ocLazyLoad,
      $injector,
      resp
    ) {
      // TODO: get back to this
      // await import('./mn_poor_mans_alerts_controller.js');
      // await $ocLazyLoad.load({ name: 'mnPoorMansAlerts' });
      // var mnPoorMansAlertsService = $injector.get('mnPoorMansAlertsService');
      // mnPoorMansAlertsService.maybeShowAlerts(resp);
    }

    async function loadAndRunLauchpad($ocLazyLoad, $injector, vm) {
      // TODO: get back to this
      // await import('./mn_settings_notifications_service.js');
      // await $ocLazyLoad.load({ name: 'mnSettingsNotificationsService' });
      // var mnSettingsNotificationsService = $injector.get(
      //   'mnSettingsNotificationsService'
      // );
      // vm.updates = await mnSettingsNotificationsService.maybeCheckUpdates({
      //   group: 'global',
      // });
      // if (vm.updates.sendStats) {
      //   vm.launchpadSource =
      //     await mnSettingsNotificationsService.buildPhoneHomeThingy({
      //       group: 'global',
      //     });
      // }
    }

    function toggleProgressBar() {
      vm.setState({ isProgressBarClosed: !vm.state.isProgressBarClosed });
    }

    function filterTasks(runningTasks, includeRebalance) {
      return (runningTasks || []).filter(function (task) {
        return MnFormatProgressMessage.transform(task, includeRebalance);
      });
    }

    function resetAutoFailOverCount() {
      var queries = [
        mnSettingsAutoFailoverService.resetAutoFailOverCount({
          group: 'global',
        }),
        mnSettingsAutoFailoverService.resetAutoReprovisionCount({
          group: 'global',
        }),
      ];

      mnPromiseHelper(vm, $q.all(queries))
        .reloadState()
        .showSpinner('resetQuotaLoading')
        .catchGlobalErrors('Unable to reset Auto-failover quota!')
        .showGlobalSuccess('Auto-failover quota reset successfully!');
    }

    function getRebalanceReport() {
      mnTasksDetails.getRebalanceReport().then(function (report) {
        var file = new Blob([JSON.stringify(report, null, 2)], {
          type: 'application/json',
          name: 'rebalanceReport.json',
        });
        saveAs(file, 'rebalanceReport.json');
      });
    }

    function activate() {
      MnSessionService.activate(vm.mnOnDestroy);

      if (
        pools.isEnterprise &&
        poolDefault.compat.atLeast76 &&
        (mnPermissions.export.getValue().cluster.admin.security.external.read ||
          mnPermissions.export.getValue().cluster.admin.security.read)
      ) {
        mnPromiseHelper(vm, mnUserRolesService.getSamlSettings()).applyToScope(
          'samlSettings'
        );
      }

      new mnPoller(vm, function () {
        return mnBucketsService.findMoxiBucket();
      })
        .subscribe('moxiBucket', vm)
        .reloadOnScopeEvent(['reloadBucketStats'])
        .cycle();

      if (mnPermissions.export.getValue().cluster.settings.read) {
        new mnPoller(vm, function () {
          return mnSettingsAutoFailoverService.getAutoFailoverSettings();
        })
          .setInterval(10000)
          .subscribe('autoFailoverSettings', vm)
          .reloadOnScopeEvent(['reloadServersPoller', 'rebalanceFinished'])
          .cycle();
      }

      if (mnPermissions.export.getValue().cluster.settings.read) {
        // loadAndRunLauchpad($ocLazyLoad, $injector, vm);
      }

      new mnEtagPoller(
        vm,
        function (previous) {
          return mnPoolDefault.get(
            {
              etag: previous ? previous.etag : '',
              waitChange: 10000,
            },
            { group: 'global' }
          );
        },
        true
      )
        .subscribe(function (resp, previous) {
          if (
            previous &&
            resp.thisNode.clusterCompatibility !=
              previous.thisNode.clusterCompatibility
          ) {
            window.location.reload();
          }

          MnAdminService.stream.getPoolsDefault.next(resp);

          if (!_.isEqual(resp, previous)) {
            MnHelperReactService.rootScopeEmitter.emit('mnPoolDefaultChanged');
          }

          if (
            Number(localStorage.getItem('uiSessionTimeout')) !==
            resp.uiSessionTimeout * 1000
          ) {
            MnHelperReactService.rootScopeEmitter.emit(
              'newSessionTimeout',
              resp.uiSessionTimeout
            );
          }

          //TODO: get back to this
          // vm.tabName = resp.clusterName;

          if (previous && !_.isEqual(resp.nodes, previous.nodes)) {
            MnHelperReactService.rootScopeEmitter.emit('nodesChanged', [
              resp.nodes,
              previous.nodes,
            ]);
          }

          if (previous && previous.buckets.uri !== resp.buckets.uri) {
            MnHelperReactService.rootScopeEmitter.emit('reloadBucketStats');
          }

          if (previous && previous.trustedCAsURI !== resp.trustedCAsURI) {
            MnHelperReactService.rootScopeEmitter.emit(
              'reloadGetPoolsDefaultTrustedCAs'
            );
          }

          if (previous && previous.serverGroupsUri !== resp.serverGroupsUri) {
            MnHelperReactService.rootScopeEmitter.emit(
              'serverGroupsUriChanged'
            );
          }

          if (previous && previous.indexStatusURI !== resp.indexStatusURI) {
            MnHelperReactService.rootScopeEmitter.emit('indexStatusURIChanged');
          }

          //TODO: get back to this
          // if (!_.isEqual(resp.alerts, (previous || {}).alerts || [])) {
          //   loadAndRunPoorMansAlertsDialog($ocLazyLoad, $injector, resp);
          // }

          // var version = mnPrettyVersionFilter(pools.implementationVersion);
          // $rootScope.mnTitle = vm.tabName + (version ? (' - ' + version) : '');

          if (previous && previous.tasks.uri != resp.tasks.uri) {
            MnHelperReactService.rootScopeEmitter.emit('reloadTasksPoller');
          }

          if (
            previous &&
            previous.checkPermissionsURI != resp.checkPermissionsURI
          ) {
            MnHelperReactService.rootScopeEmitter.emit('reloadPermissions');
          }
        })
        .cycle();

      if (mnPermissions.export.getValue().cluster.tasks.read) {
        if (
          vm.props.pools.isEnterprise &&
          vm.props.poolDefault.compat.atLeast65
        ) {
          new mnPoller(vm, function () {
            return mnSettingsClusterService.getPendingRetryRebalance({
              group: 'global',
            });
          })
            .setInterval(function (resp) {
              return resp.data.retry_after_secs ? 1000 : 3000;
            })
            .subscribe(function (resp) {
              vm.retryRebalance = resp.data;
            })
            .cycle();
        }

        var tasksPoller = new mnPoller(vm, function (prevTask) {
          return mnTasksDetails
            .getFresh({ group: 'global' })
            .then(function (tasks) {
              if (vm.props.poolDefault.compat.atLeast65) {
                if (tasks.tasksRebalance.status == 'notRunning') {
                  if (
                    !tasks.tasksRebalance.masterRequestTimedOut &&
                    prevTask &&
                    tasks.tasksRebalance.lastReportURI !=
                      prevTask.tasksRebalance.lastReportURI
                  ) {
                    mnTasksDetails.clearRebalanceReportCache(
                      prevTask.tasksRebalance.lastReportURI
                    );
                  }
                  if (mnPermissions.export.getValue().cluster.admin.logs.read) {
                    return mnTasksDetails
                      .getRebalanceReport(tasks.tasksRebalance.lastReportURI)
                      .then(function (rv) {
                        if (rv.data.stageInfo) {
                          tasks.tasksRebalance.stageInfo = rv.data.stageInfo;
                          tasks.tasksRebalance.completionMessage =
                            rv.data.completionMessage;
                        }
                        return tasks;
                      });
                  }
                }
                return tasks;
              }
              return tasks;
            });
        })
          .setInterval(function (result) {
            return (
              (_.chain(result.tasks)
                .pluck('recommendedRefreshPeriod')
                .compact()
                .min()
                .value() *
                1000) >>
                0 || 10000
            );
          })
          .subscribe(function (tasks, prevTask) {
            vm.showTasksSpinner = false;
            if (!_.isEqual(tasks, prevTask)) {
              MnHelperReactService.rootScopeEmitter.emit(
                'mnTasksDetailsChanged'
              );
            }

            var isRebalanceFinished =
              tasks.tasksRebalance &&
              tasks.tasksRebalance.status !== 'running' &&
              prevTask &&
              prevTask.tasksRebalance &&
              prevTask.tasksRebalance.status === 'running';
            if (isRebalanceFinished) {
              MnHelperReactService.rootScopeEmitter.emit('rebalanceFinished');
            }

            if (
              !vm.state.isProgressBarClosed &&
              !filterTasks(tasks.running).length &&
              !tasks.tasksRebalance.stageInfo &&
              prevTask &&
              filterTasks(prevTask.running).length
            ) {
              vm.setState({ isProgressBarClosed: true });
            }

            var stageInfo = {
              services: {},
              startTime: null,
              completedTime: {
                status: true,
              },
            };
            var serverStageInfo =
              tasks.tasksRebalance.stageInfo ||
              (tasks.tasksRebalance.previousRebalance &&
                tasks.tasksRebalance.previousRebalance.stageInfo);

            if (serverStageInfo) {
              var services = Object.keys(serverStageInfo).sort(function (a, b) {
                if (!serverStageInfo[a].timeTaken) {
                  return 1;
                }
                if (!serverStageInfo[b].startTime) {
                  return -1;
                }
                if (
                  new Date(serverStageInfo[a].startTime) >
                  new Date(serverStageInfo[b].startTime)
                ) {
                  return 1;
                } else {
                  return -1;
                }
              });

              stageInfo.services = services.map(function (key) {
                var value = serverStageInfo[key];
                value.name = key;
                var details = Object.keys(value.details || {});
                // .sort(function (a, b) {
                //   return new Date(value.details[a].startTime) -
                //     new Date(value.details[b].startTime);
                // });

                value.details = details.map(function (bucketName) {
                  value.details[bucketName].name = bucketName;
                  return value.details[bucketName];
                });

                if (value.startTime) {
                  if (
                    !stageInfo.startTime ||
                    stageInfo.startTime > new Date(value.startTime)
                  ) {
                    stageInfo.startTime = new Date(value.startTime);
                  }
                }
                if (value.completedTime) {
                  value.completedTime = new Date(value.completedTime);
                  if (
                    !stageInfo.completedTime.time ||
                    stageInfo.completedTime.time < value.completedTime
                  ) {
                    stageInfo.completedTime.time = new Date(
                      value.completedTime
                    );
                  }
                } else {
                  stageInfo.completedTime.status = false;
                }
                return value;
              });

              tasks.tasksRebalance.stageInfo = stageInfo;
            }

            if (tasks.inRebalance) {
              if (!prevTask) {
                vm.setState({ isProgressBarClosed: false });
              } else {
                if (
                  !prevTask.tasksRebalance ||
                  prevTask.tasksRebalance.status !== 'running'
                ) {
                  vm.setState({ isProgressBarClosed: false });
                }
              }
            }

            if (
              tasks.tasksRebalance.errorMessage &&
              mnAlertsService.isNewAlert({ id: tasks.tasksRebalance.statusId })
            ) {
              mnAlertsService.setAlert(
                'error',
                tasks.tasksRebalance.errorMessage,
                null,
                tasks.tasksRebalance.statusId
              );
            }
            vm.setState({
              tasks: tasks,
            });
            MnHelperReactService.tasks.next(tasks);
          }, vm)
          .cycle();
      }

      MnHelperReactService.rootScopeEmitter.on(
        'reloadTasksPoller',
        function (event, params) {
          if (!params || !params.doNotShowSpinner) {
            vm.showTasksSpinner = true;
          }
          if (tasksPoller) {
            tasksPoller.reload(true);
          }
        }
      );

      MnHelperReactService.rootScopeEmitter.on(
        'reloadBucketStats',
        function () {
          mnBucketsService.clearCache();
          mnBucketsService.getBucketsByType();
        }
      );
      MnHelperReactService.rootScopeEmitter.emit('reloadBucketStats');

      vm.mainSpinnerCounter = mnHelper.mainSpinnerCounter.value();
      MnHelperReactService.async(vm, 'mainSpinnerCounter');
    }
  }
  render() {
    const vm = this;
    const {
      mainSpinnerCounter,
      alerts,
      tasks,
      lostConnState,
      autoFailoverSettings,
      poolDefault,
      rbac,
      moxiBucket,
      clientAlerts,
    } = this.state;

    const { pools } = vm.props;

    return (
      <ModalProvider>
        {/**TODO: implement launchpad */}
        {/* Launchpad */}
        {/* {vm.props.rbac.cluster.settings.read && (
          <div
            mn-launchpad
            launchpad-source={vm.launchpadSource}
            launchpad-id={vm.launchpadId}
          />
        )} */}
        <UIView name="lostConnection" />

        {/* Header Row */}
        <div className="row">
          <div className="red-1 nowrap text-smaller margin-left-1">
            {vm.isDeveloperPreview && (
              <span>
                PREVIEW MODE · UNSUPPORTED · NOT FOR USE IN PRODUCTION
              </span>
            )}
          </div>
          <nav className="nav-header">
            {/* Activity Button */}
            {rbac.cluster.tasks.read && (
              <a onClick={vm.toggleProgressBar} className="activities">
                activity
                {vm.filterTasks(tasks.running, true).length > 0 && (
                  <span className="label badge">
                    {vm.filterTasks(tasks.running, true).length}
                  </span>
                )}
              </a>
            )}

            {/* Activity Panel */}
            {rbac.cluster.tasks.read && (
              <div className="relative inline">
                {!vm.state.isProgressBarClosed && (
                  <MnDragAndDrop
                    baseCornerRight={true}
                    className="tasks-progress panel dialog-med activity-panel enable-ng-animation max-height-550 permanent-scroll"
                  >
                    <div className="text-right grayblack-2">
                      <span
                        onClick={vm.toggleProgressBar}
                        className="cursor-pointer close-x"
                      >
                        X
                      </span>
                    </div>

                    {tasks.tasksRebalance?.statusId && (
                      <h4>
                        {tasks.isSubtypeFailover ? 'Failover' : 'Rebalance'}
                      </h4>
                    )}

                    {tasks.tasksRebalance && (
                      <>
                        {tasks.tasksRebalance.statusId && (
                          <p className="desc relative">
                            {tasks.tasksRebalance.stageInfo.startTime && (
                              <span className="nowrap">
                                <strong>start</strong>
                                {dayjs
                                  .utc(tasks.tasksRebalance.stageInfo.startTime)
                                  .format('d MMM HH:mm:ss')}
                              </span>
                            )}
                            {tasks.tasksRebalance.stageInfo.completedTime
                              .status && (
                              <span className="nowrap margin-left-half">
                                <strong>complete</strong>
                                {dayjs
                                  .utc(
                                    tasks.tasksRebalance.stageInfo.completedTime
                                      .time
                                  )
                                  .format('d MMM HH:mm:ss')}
                              </span>
                            )}
                            <strong>status</strong>
                            {tasks.tasksRebalance.status === 'running'
                              ? 'in progress'
                              : tasks.tasksRebalance.errorMessage
                                ? 'failed'
                                : 'completed'}
                            <span
                              className={`nowrap ${tasks.tasksRebalance.status === 'running' ? 'rebalance-status-inprogress' : ''}`}
                            >
                              {tasks.tasksRebalance.errorMessage && (
                                <OverlayTrigger
                                  placement="bottom"
                                  overlay={
                                    <Tooltip>
                                      {tasks.tasksRebalance.errorMessage}
                                    </Tooltip>
                                  }
                                >
                                  <span className="fa-stack icon-info">
                                    <span className="icon fa-circle-thin fa-stack-2x"></span>
                                    <span className="icon fa-info fa-stack-1x"></span>
                                  </span>
                                </OverlayTrigger>
                              )}
                            </span>
                          </p>
                        )}

                        {tasks.tasksRebalance.completionMessage && (
                          <div
                            className={`alert margin-bottom-1 row ${
                              tasks.tasksRebalance.errorMessage
                                ? 'alert-error'
                                : 'alert-success'
                            }`}
                          >
                            <p>{tasks.tasksRebalance.completionMessage}</p>
                            {poolDefault.isEnterprise && (
                              <div className="nowrap">
                                {/* TODO: implement download report */}
                                <button
                                  // onClick={vm.getRebalanceReport}
                                  // download="rebalanceReport.json"
                                  className="outline tight margin-right-half"
                                >
                                  Download Report
                                </button>
                              </div>
                            )}
                          </div>
                        )}

                        {/* Rebalance Services Info */}
                        {poolDefault.isEnterprise &&
                          tasks.tasksRebalance.stageInfo?.services?.map(
                            (service, index) => (
                              <div key={service.name + index}>
                                <div className="row margin-top-half margin-bottom-half">
                                  <label className="initialcaps">
                                    {service.name}
                                  </label>
                                  {service.timeTaken !== false ? (
                                    <span className="rebalance-stage-status">
                                      {service.completedTime && (
                                        <span className="rebalance-stage-success">
                                          completed
                                        </span>
                                      )}
                                      {!service.completedTime &&
                                        !tasks.tasksRebalance.errorMessage && (
                                          <span
                                            className={`rebalance-stage-inprogress ${
                                              tasks.tasksRebalance.status !==
                                              'running'
                                                ? 'rebalance-stage-inprogress-paused'
                                                : ''
                                            }`}
                                          >
                                            elapsed
                                          </span>
                                        )}
                                      {!service.completedTime &&
                                        tasks.tasksRebalance.errorMessage && (
                                          <span className="rebalance-stage-error">
                                            failed
                                          </span>
                                        )}
                                      {mnMsToTime(service.timeTaken)}
                                    </span>
                                  ) : (
                                    <span>- - -</span>
                                  )}
                                </div>

                                {/* Sub Stages */}
                                {Object.entries(service.subStages || {}).map(
                                  ([name, subStage]) => (
                                    <div
                                      key={name}
                                      className="row margin-left-half margin-bottom-half margin-top-half"
                                    >
                                      <label className="ellipsis" title={name}>
                                        {name === 'deltaRecovery'
                                          ? 'Delta Recovery Warmup'
                                          : name}
                                      </label>
                                      {subStage.timeTaken !== false ? (
                                        <span className="rebalance-stage-status nowrap">
                                          {subStage.completedTime && (
                                            <span className="rebalance-stage-success">
                                              completed
                                            </span>
                                          )}
                                          {!subStage.completedTime &&
                                            !tasks.tasksRebalance
                                              .errorMessage && (
                                              <span className="rebalance-stage-inprogress">
                                                elapsed
                                              </span>
                                            )}
                                          {!subStage.completedTime &&
                                            tasks.tasksRebalance
                                              .errorMessage && (
                                              <span className="rebalance-stage-error">
                                                failed
                                              </span>
                                            )}
                                          {mnMsToTime(subStage.timeTaken)}
                                        </span>
                                      ) : (
                                        <span>- - -</span>
                                      )}
                                    </div>
                                  )
                                )}

                                {/* Bucket Info */}
                                {service.details?.map((bucketInfo) => (
                                  <div key={bucketInfo.name}>
                                    <div className="row margin-bottom-half">
                                      <label
                                        onClick={() =>
                                          this.setState((prev) => ({
                                            showBucket: {
                                              ...prev.showBucket,
                                              [bucketInfo.name]:
                                                !prev.showBucket?.[
                                                  bucketInfo.name
                                                ],
                                            },
                                          }))
                                        }
                                        className={`disclosure cursor-pointer margin-left-half ellipsis ${
                                          this.state.showBucket?.[
                                            bucketInfo.name
                                          ]
                                            ? 'disclosed'
                                            : ''
                                        }`}
                                      >
                                        {/* TODO: fix but when bucket name is displayed as index after rebalance is completed */}
                                        {bucketInfo.name}
                                      </label>
                                      <span className="nowrap text-smaller text-right">
                                        vBuckets moved:{' '}
                                        {bucketInfo.vbucketLevelInfo.move
                                          .totalCount -
                                          bucketInfo.vbucketLevelInfo.move
                                            .remainingCount +
                                          ' of ' +
                                          bucketInfo.vbucketLevelInfo.move
                                            .totalCount}{' '}
                                        &nbsp;
                                        {(
                                          ((bucketInfo.vbucketLevelInfo.move
                                            .totalCount -
                                            bucketInfo.vbucketLevelInfo.move
                                              .remainingCount) /
                                            bucketInfo.vbucketLevelInfo.move
                                              .totalCount) *
                                          100
                                        ).toFixed(0)}
                                        %
                                      </span>
                                    </div>
                                    {/* TODO: implement bucket info */}
                                    {this.state.showBucket?.[
                                      bucketInfo.name
                                    ] && (
                                      <div className="indent-1-5 margin-bottom-1 margin-top-half">
                                        {/* Replication Info */}
                                        {bucketInfo.replicationInfo && (
                                          <div className="rebalance-stage-details">
                                            <div className="cbui-table-header padding-left-0 border-0 min-height-0">
                                              <div className="cbui-table-cell grayblack-0 bold">
                                                node
                                              </div>
                                              <div className="cbui-table-cell grayblack-0 bold">
                                                incoming docs
                                              </div>
                                              <div className="cbui-table-cell grayblack-0 bold">
                                                outgoing docs
                                              </div>
                                            </div>
                                            {Object.entries(
                                              bucketInfo.replicationInfo
                                            ).map(([node, details]) => (
                                              <div
                                                key={node}
                                                className="cbui-tablerow padding-left-0"
                                              >
                                                <div className="cbui-table-cell">
                                                  {node}
                                                </div>
                                                <div className="cbui-table-cell">
                                                  {details.inDocsTotal -
                                                    details.inDocsLeft +
                                                    ' of ' +
                                                    details.inDocsTotal}
                                                </div>
                                                <div className="cbui-table-cell">
                                                  {details.outDocsTotal -
                                                    details.outDocsLeft +
                                                    ' of ' +
                                                    details.outDocsTotal}
                                                </div>
                                              </div>
                                            ))}
                                          </div>
                                        )}

                                        {/* Compaction Info */}
                                        {bucketInfo.compactionInfo && (
                                          <>
                                            <h6
                                              onClick={() =>
                                                this.setState((prev) => ({
                                                  showCompaction: {
                                                    ...prev.showCompaction,
                                                    [bucketInfo.name]:
                                                      !prev.showCompaction?.[
                                                        bucketInfo.name
                                                      ],
                                                  },
                                                }))
                                              }
                                              className={`disclosure cursor-pointer ${
                                                this.state.showCompaction?.[
                                                  bucketInfo.name
                                                ]
                                                  ? 'disclosed'
                                                  : ''
                                              }`}
                                            >
                                              Views Compaction
                                            </h6>
                                            {this.state.showCompaction?.[
                                              bucketInfo.name
                                            ] && (
                                              <div className="rebalance-stage-details">
                                                <div className="cbui-table-header padding-left-0 border-0 min-height-0">
                                                  <div className="cbui-table-cell grayblack-0 bold">
                                                    node
                                                  </div>
                                                  <div className="cbui-table-cell">
                                                    &nbsp;
                                                  </div>
                                                  <div className="cbui-table-cell grayblack-0 bold">
                                                    average time
                                                  </div>
                                                </div>
                                                {Object.entries(
                                                  bucketInfo.compactionInfo
                                                    .perNode
                                                ).map(([node, v]) => (
                                                  <div
                                                    key={node}
                                                    className="cbui-tablerow padding-left-0"
                                                  >
                                                    <div className="cbui-table-cell">
                                                      {node}
                                                    </div>
                                                    <div className="cbui-table-cell">
                                                      &nbsp;
                                                    </div>
                                                    <div className="cbui-table-cell">
                                                      {(
                                                        v.averageTime / 1000
                                                      ).toFixed(4)}
                                                    </div>
                                                  </div>
                                                ))}
                                              </div>
                                            )}
                                          </>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                ))}

                                {/* Service Progress Bar */}
                                {service.completedTime === false &&
                                  service.totalProgress !== undefined &&
                                  !tasks.tasksRebalance.errorMessage && (
                                    <div className="zero-content margin-top-1">
                                      <div className="text-small text-left break-word">
                                        {`rebalancing ${service.name} service `}
                                        <span>
                                          {service.totalProgress.toFixed(1) +
                                            '%'}
                                        </span>
                                      </div>
                                      <div className="bar-wrapper">
                                        <div
                                          className="bar positive"
                                          style={{
                                            width: service.totalProgress + '%',
                                          }}
                                        >
                                          <div></div>
                                        </div>
                                        <div
                                          className="bar negative"
                                          style={{
                                            width:
                                              100 - service.totalProgress + '%',
                                          }}
                                        >
                                          <div></div>
                                        </div>
                                      </div>
                                    </div>
                                  )}
                              </div>
                            )
                          )}

                        {/* Stop Rebalance Button */}
                        {poolDefault.rebalancing &&
                          rbac.cluster.pools.write && (
                            <div className="text-right margin-bottom-1 margin-top-half">
                              <button
                                className="red"
                                onClick={vm.postStopRebalance}
                              >
                                Stop
                              </button>
                            </div>
                          )}
                      </>
                    )}

                    {/* Running Tasks */}
                    {vm.filterTasks(tasks.running).map((task) => (
                      <div key={task.id} className="zero-content margin-top-1">
                        <div className="text-small text-left break-word">
                          {MnFormatProgressMessage.transform(task) + ' '}
                          {task.progress !== undefined && (
                            <span>{task.progress.toFixed(1) + '%'}</span>
                          )}
                        </div>
                        {task.type !== 'loadingSampleBucket' &&
                          task.type !== 'orphanBucket' && (
                            <div className="bar-wrapper">
                              <div
                                className="bar positive"
                                style={{ width: task.progress + '%' }}
                              >
                                <div></div>
                              </div>
                              <div
                                className="bar negative"
                                style={{ width: 100 - task.progress + '%' }}
                              >
                                <div></div>
                              </div>
                            </div>
                          )}
                      </div>
                    ))}
                  </MnDragAndDrop>
                )}
              </div>
            )}

            {/* Internal Settings */}
            {vm.enableInternalSettings && rbac.cluster.admin.settings.write && (
              <a onClick={vm.runInternalSettingsDialog}>
                edit internal settings
              </a>
            )}

            {/* Developer Settings */}
            {vm.enableDeveloperSettings && (
              <a onClick={vm.runDeveloperSettingsDialog}>
                edit developer settings
              </a>
            )}

            {/* Help Dropdown */}
            <Dropdown className="mn-dropdown-menu">
              <Dropdown.Toggle variant="link" id="dropdown-basic" as="a">
                help <span className="has-menu">&nbsp;</span>
              </Dropdown.Toggle>

              <Dropdown.Menu className="dropdown-menu-select-like">
                <Dropdown.Item
                  as="a"
                  href={`https://docs.couchbase.com/server/${vm.implementationVersion}/introduction/intro.html`}
                  rel="noopener noreferrer"
                  target="_blank"
                >
                  Documentation
                  <br />
                </Dropdown.Item>
                <Dropdown.Item
                  as="a"
                  href={
                    poolDefault.isEnterprise
                      ? 'http://support.couchbase.com'
                      : 'http://www.couchbase.com/communities/'
                  }
                  rel="noopener noreferrer"
                  target="cbforums"
                >
                  Couchbase Support
                  <br />
                  {poolDefault.isEnterprise ? (
                    <desc>For Enterprise Edition subscription customers</desc>
                  ) : (
                    <desc>For Community Edition users</desc>
                  )}
                </Dropdown.Item>
                <Dropdown.Item as="a" onClick={vm.showClusterInfoDialog}>
                  Get Cluster Summary Info
                  <br />
                  <desc>
                    For complete info, use &nbsp;
                    <UISref
                      to="app.admin.logs.collectInfo.form"
                      className="blue-1"
                    >
                      <span>Collect Info</span>
                    </UISref>
                  </desc>
                </Dropdown.Item>
                <Dropdown.Item
                  as="a"
                  href={`https://docs.couchbase.com/server/${vm.majorMinorVersion}/install/install-platforms.html#supported-browsers`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="blue-1"
                >
                  Supported Browsers
                </Dropdown.Item>
              </Dropdown.Menu>
            </Dropdown>

            {/* User Dropdown */}
            <Dropdown className="mn-dropdown-menu">
              <Dropdown.Toggle
                variant="link"
                as="a"
                className="nowrap ellipsis max-width-3"
                id="user-dropdown"
              >
                {vm.user.id}
                <span className="has-menu">&nbsp;</span>
              </Dropdown.Toggle>

              <Dropdown.Menu className="dropdown-menu-select-like">
                {pools.isEnterprise &&
                  (vm.user.domain === 'local' ||
                    vm.user.domain === 'admin') && (
                    <Dropdown.Item as="a" onClick={vm.showResetPasswordDialog}>
                      Change Password
                    </Dropdown.Item>
                  )}
                <Dropdown.Item
                  as="a"
                  onClick={vm.logout}
                  className="ellipsis max-width-4"
                >
                  Sign Out {vm.user.id}
                </Dropdown.Item>
              </Dropdown.Menu>
            </Dropdown>
          </nav>
        </div>

        {/* Header */}
        <header>
          <UISref to="app.admin.overview.statistics">
            <a className="logobug-wrapper">
              <img
                src="../cb_logo_bug_white_2.svg"
                width="48"
                height="48"
                alt="Couchbase Server"
                className="logobug"
                title={`Couchbase Server ${vm.implementationVersion}`}
              />
            </a>
          </UISref>
          <h1>
            <UISref to="app.admin.overview.statistics">
              <a className="resp-txt-xsml ellipsis">
                {vm.tabName && 'Cluster '}
                {vm.tabName}
              </a>
            </UISref>
            <span className="resp-hide-xsml">
              <span className="icon fa-angle-right"></span>
            </span>
            {/* TODO: Implement parent navigation */}
            {/* {UIRouter.stateService.$current.data.parent && (
              <>
                <a
                  href={UIRouter.stateService.$current.data.parent.link}
                  onClick={(e) => {
                    e.preventDefault();
                    // TODO: Implement ui-state navigation
                  }}
                >
                  {UIRouter.stateService.$current.data.parent.name}
                </a>
                <span className="icon fa-angle-right"></span>
              </>
            )}
            <span>{UIRouter.stateService.$current.data.title}</span> */}
          </h1>

          {/* Header Depots */}
          <div className="row flex-right">
            <MnElementDepot name="header" />
            <MnElementDepot name="actions" />
            <span
              className="menu-icon"
              onClick={() =>
                this.setState((prev) => ({ showRespMenu: !prev.showRespMenu }))
              }
            >
              <span className="icon fa-navicon"></span>
            </span>
          </div>
        </header>

        <MnElementDepot name="subnav" />

        {/* Alerts */}
        <div className="alert-wrapper fix-position-bl">
          <MnElementDepot name="alerts" />

          {/* Retry Rebalance Alert */}
          {vm.retryRebalance &&
            vm.retryRebalance.retry_rebalance !== 'not_pending' && (
              <div className="alert alert-warning">
                <p>
                  {vm.retryRebalance.type === 'rebalance'
                    ? 'Rebalance'
                    : 'Graceful Failover'}
                  failed. It will be automatically retried in{' '}
                  {vm.retryRebalance.retry_after_secs}
                  <br />
                  {rbac.cluster.pools.write && (
                    <a
                      onClick={() =>
                        vm.postCancelRebalanceRetry(
                          vm.retryRebalance.rebalance_id
                        )
                      }
                    >
                      CANCEL RETRY
                    </a>
                  )}
                </p>
              </div>
            )}

          {/* Loading Samples Alert */}
          {tasks.isLoadingSamples &&
            rbac.cluster.tasks.read &&
            !poolDefault.balanced &&
            !clientAlerts.rebalanceDataLoading && (
              <div className="alert alert-warning">
                <p>
                  Warning: Rebalance is not available until data loading is
                  completed.
                </p>
                <a
                  onClick={() => vm.closeCustomAlert('rebalanceDataLoading')}
                  className="close"
                >
                  X
                </a>
              </div>
            )}

          {/* Moxi Bucket Alert */}
          {!poolDefault.compat.atLeast55 &&
            moxiBucket &&
            !poolDefault.balanced &&
            !clientAlerts.moxiBucket && (
              <div className="alert alert-warning">
                <p>
                  Your Couchbase bucket <i>{vm.moxiBucket.name}</i> has an
                  active dedicated port, also known as a Moxi port. Moxi is
                  deprecated and will be removed in a future release.
                  <br />
                  You can run the CLI command <i>
                    couchbase-cli bucket-edit
                  </i>{' '}
                  command with the <i>--remove-bucket-port</i> option to remove
                  the Moxi port.
                </p>
                <a
                  onClick={() => vm.closeCustomAlert('moxiBucket')}
                  className="close"
                >
                  X
                </a>
              </div>
            )}

          {/* Compatibility Alert */}
          {!Object.values(poolDefault.compat).every(Boolean) &&
            !clientAlerts.hideCompatibility && (
              <div className="alert alert-warning">
                <p>
                  This cluster contains multiple server versions and is running
                  in
                  {decodeCompatVersion(
                    poolDefault.thisNode.clusterCompatibility
                  )}
                  compatibility mode.
                </p>
                <a
                  onClick={() => vm.closeCustomAlert('hideCompatibility')}
                  className="close"
                >
                  X
                </a>
              </div>
            )}

          {/* Failover Warnings */}
          {poolDefault.failoverWarnings
            .filter(
              (warning) =>
                warning &&
                warning !== 'failoverNeeded' &&
                !poolDefault.rebalancing &&
                !clientAlerts[warning]
            )
            .map((warning) => (
              <div key={warning} className="alert alert-warning">
                <p>Warning: {formatFailoverWarnings(warning)}</p>
                <a
                  onClick={() => vm.closeCustomAlert(warning)}
                  className="close"
                >
                  X
                </a>
              </div>
            ))}

          {/* Auto Failover Alert */}
          {autoFailoverSettings?.count > 0 &&
            rbac.cluster.settings.read &&
            !clientAlerts.maxCount && (
              <div className="alert alert-warning">
                <p>
                  A server was automatically failed over. Failover quota
                  used/max:
                  {autoFailoverSettings.count}/{autoFailoverSettings.maxCount}
                </p>
                <a
                  onClick={() => vm.closeCustomAlert('maxCount')}
                  className="close"
                >
                  X
                </a>
              </div>
            )}

          {/* CE Nodes Limit Alert */}
          {!pools.isEnterprise &&
            poolDefault.nodes.length > 5 &&
            !clientAlerts.ceNodesLimit && (
              <div className="alert alert-warning">
                <p>
                  Warning: This cluster is running {poolDefault.nodes.length}{' '}
                  servers. The Couchbase Community Edition license allows for no
                  more than 5 servers. See
                  <a
                    href="https://blog.couchbase.com/couchbase-modifies-license-free-community-edition-package/"
                    rel="noopener noreferrer"
                    target="_blank"
                  >
                    this link
                  </a>
                  for details.
                </p>
                <a
                  onClick={() => vm.closeCustomAlert('ceNodesLimit')}
                  className="close"
                >
                  X
                </a>
              </div>
            )}

          {/* Max Auto Failover Alert */}
          {(autoFailoverSettings?.count === autoFailoverSettings?.maxCount ||
            (!poolDefault.compat.atLeast55 &&
              !pools.isEnterprise &&
              autoFailoverSettings?.count === 1)) && (
            <div className="alert alert-warning">
              <p>
                The maximum number of nodes have been automatically failed over.
                Auto-failover is disabled until you reset it.
                <br />
                {rbac.cluster.settings.write && (
                  <a onClick={vm.resetAutoFailOverCount}>Reset Auto-Failover</a>
                )}
              </p>
            </div>
          )}

          {/* Lost Connection Alert */}
          {lostConnState.isActive && (
            <div className="alert alert-warning">
              <p>
                Difficulties communicating with the cluster. Displaying cached
                information.
              </p>
            </div>
          )}

          {/* Dynamic Alerts */}
          {alerts.map((alert, index) => (
            <div
              key={index}
              className={`animate-alert alert overflow-wrap overflow-hidden enable-ng-animation max-height-10 alert-${alert.type}`}
            >
              <p className="padding-1">
                <span className="margin-right-half margin-left-half max-height-4 overflow-y-auto inline padding-left-half padding-right-half permanent-scroll">
                  {alert.msg}
                </span>
              </p>
              {alert.type !== 'success' && (
                <a onClick={() => vm.closeAlert(alert)} className="close">
                  X
                </a>
              )}
            </div>
          ))}
        </div>

        {/* Main Content */}
        <main>
          {/* Navigation Sidebar */}
          {/** TODO: think whether we need pluggable stuff
           * mn-pluggable-ui-tabs
           * mn-tab-bar-name="adminTab"
           */}
          <nav
            className={`nav-sidebar ${vm.showRespMenu ? 'resp-show-menu' : ''} ${
              vm.props.poolDefault.hideNavSidebar ? 'nav-sidebar-hidden' : ''
            }`}
            onClick={() =>
              this.setState((prev) => ({ showRespMenu: !prev.showRespMenu }))
            }
          >
            <UISrefActive class="currentnav">
              <UISref to="app.admin.overview.statistics">
                <a>Dashboard</a>
              </UISref>
            </UISrefActive>
            <UISrefActive class="currentnav">
              <a>
                <UISref to="app.admin.servers.list">
                  <span>Servers</span>
                </UISref>
                <UISref to="app.admin.groups">
                  <span />
                </UISref>
              </a>
            </UISrefActive>
            {rbac.cluster.bucket['.'].settings.read && (
              <UISrefActive class="currentnav">
                <a>
                  <UISref to="app.admin.buckets">
                    <span>Buckets</span>
                  </UISref>
                  <UISref to="app.admin.collections">
                    <span />
                  </UISref>
                </a>
              </UISrefActive>
            )}
            {rbac.cluster.tasks.read && (
              <UISrefActive class="currentnav">
                <UISref to="app.admin.replications">
                  <a>XDCR</a>
                </UISref>
              </UISrefActive>
            )}
            {rbac.cluster.admin.security.read && (
              <UISrefActive class="currentnav">
                <UISref to="app.admin.security.roles.user">
                  <a>Security</a>
                </UISref>
              </UISrefActive>
            )}
            <UISrefActive class="currentnav">
              <UISref to="app.admin.settings.cluster">
                <a>
                  <OverlayTrigger
                    placement="right"
                    overlay={
                      <Tooltip>
                        A newer version of Couchbase Server is available on the
                        General Settings page...
                      </Tooltip>
                    }
                  >
                    <span className="label neutral badge notify">i</span>
                  </OverlayTrigger>
                  &nbsp;Settings
                </a>
              </UISref>
            </UISrefActive>
            {rbac.cluster.logs.read && (
              <UISrefActive class="currentnav">
                <UISref to="app.admin.logs">
                  <a>Logs</a>
                </UISref>
              </UISrefActive>
            )}
            <div className="margin-bottom-1"></div>
            <div mn-pluggable-ui-tabs mn-tab-bar-name="workbenchTab">
              {rbac.cluster.collection['.:.:.'].n1ql.index.read && (
                <UISrefActive class="currentnav">
                  <UISref to="app.admin.gsi">
                    <a>GSI</a>
                  </UISref>
                </UISrefActive>
              )}
            </div>
            {rbac.cluster.bucket['.'].settings.read &&
              rbac.cluster.bucket['.'].views.read && (
                <UISrefActive class="currentnav">
                  <UISref
                    to="app.admin.views"
                    params={{
                      bucket: rbac.bucketNames['.views!read'][0] || '',
                    }}
                  >
                    <a>Views</a>
                  </UISref>
                </UISrefActive>
              )}
            <div
              className="sidebar-closer resp-hide-med"
              title="hide sidebar"
              onClick={() => (poolDefault.hideNavSidebar = true)}
            >
              <span className="icon fa-chevron-left"></span>
            </div>
          </nav>

          {/* Sidebar Toggle */}
          <div
            className={`sidebar-opener ${poolDefault.hideNavSidebar ? 'show' : ''}`}
            title="show sidebar"
            onClick={() => (poolDefault.hideNavSidebar = false)}
          >
            <span className="icon fa-chevron-right"></span>
          </div>

          {/* Main Content Area */}
          <div
            className={`main-content min-width-zero delayed-spinner expanded-spinner fixed-spinner width-12 ${
              mainSpinnerCounter ? 'mn-main-spinner-active' : ''
            }`}
          >
            {/* <MnSpinner mnSpinner={!!mainSpinnerCounter}> */}
            <UIView name="main" className="width-12" autoscroll={false} />
            {/* </MnSpinner> */}
          </div>
        </main>
      </ModalProvider>
    );
  }
}

export { MnAdminComponent };
