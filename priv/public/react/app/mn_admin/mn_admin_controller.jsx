import React from 'react';
import { takeUntil } from 'rxjs/operators';
import { MnElementDepot } from '../mn.element.crane';
import { UIView } from '@uirouter/react';
import { ModalProvider } from '../uib/template/modal/window.and.backdrop';
import { MnLifeCycleHooksToStream } from 'mn.core';
import mnAlertsService from '../components/mn_alerts';
import { mnEtagPoller, mnPoller } from '../components/mn_poll';
import { MnAdminService } from '../mn.admin.service';
import { MnHelperReactService } from '../mn.helper.react.service';
import mnPoolDefault from '../components/mn_pool_default';
import mnBucketsService from './mn_buckets_service.js';
import mnPermissions from '../components/mn_permissions.js';
import { MnSpinner } from '../components/directives/mn_spinner.jsx';
import mnSettingsClusterService from './mn_settings_cluster_service.js';
import mnTasksDetails from '../components/mn_tasks_details.js';
import mnHelper from '../components/mn_helper.js';
import _ from 'lodash';
import { MnFormatProgressMessage } from '../mn.pipes.js';

class MnAdminComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      alerts: [],
      tasks: [],
      mainSpinnerCounter: 0,
    };
  }
  componentDidMount() {
    const vm = this;
    const $scope = vm;

    vm.filterTasks = filterTasks;

    function filterTasks(runningTasks, includeRebalance) {
      return (runningTasks || []).filter(function (task) {
        return MnFormatProgressMessage.transform(task, includeRebalance);
      });
    }

    mnAlertsService.alerts
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((alerts) => {
        this.setState({ alerts });
      });

    vm.closeAlert = mnAlertsService.removeItem;

    new mnEtagPoller(
      $scope,
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
          MnHelperReactService.rootScopeEmitter.emit('serverGroupsUriChanged');
        }

        if (previous && previous.indexStatusURI !== resp.indexStatusURI) {
          MnHelperReactService.rootScopeEmitter.emit('indexStatusURIChanged');
        }

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
        new mnPoller($scope, function () {
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

      var tasksPoller = new mnPoller($scope, function (prevTask) {
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
            MnHelperReactService.rootScopeEmitter.emit('mnTasksDetailsChanged');
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
            !vm.isProgressBarClosed &&
            !filterTasks(tasks.running).length &&
            !tasks.tasksRebalance.stageInfo &&
            prevTask &&
            filterTasks(prevTask.running).length
          ) {
            vm.isProgressBarClosed = true;
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
                  stageInfo.completedTime.time = new Date(value.completedTime);
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
              vm.isProgressBarClosed = false;
            } else {
              if (
                !prevTask.tasksRebalance ||
                prevTask.tasksRebalance.status !== 'running'
              ) {
                vm.isProgressBarClosed = false;
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
    const { mainSpinnerCounter } = this.state;
    return (
      <ModalProvider>
        <div className="alert-wrapper fix-position-bl">
          <MnElementDepot name="alerts" />
          {vm.state.alerts.map((alert, index) => (
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
        <div
          className={`main-content min-width-zero delayed-spinner expanded-spinner fixed-spinner width-12 ${mainSpinnerCounter ? 'mn-main-spinner-active' : ''}`}
        >
          <MnSpinner mnSpinner={!!mainSpinnerCounter}>
            <UIView className="width-12" autoscroll={false} />
          </MnSpinner>
          {/* <div
              ui-view="main"
              autoscroll="false"
              class="width-12"></div> */}
        </div>
      </ModalProvider>
    );
  }
}

export { MnAdminComponent };
