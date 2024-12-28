import React from 'react';
import { takeUntil } from 'rxjs/operators';
import { MnElementDepot } from "../mn.element.crane";
import { UIView } from "@uirouter/react";
import { ModalProvider } from "../uib/template/modal/window.and.backdrop";
import { MnLifeCycleHooksToStream } from "mn.core";
import mnAlertsService from "../components/mn_alerts";
import { mnEtagPoller } from "../components/mn_poll";
import { MnAdminService } from "../mn.admin.service";
import { MnHelperReactService } from '../mn.helper.react.service';
import  mnPoolDefault from "../components/mn_pool_default";
import _ from 'lodash';

class MnAdminComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      alerts: []
    };
  }
  componentDidMount() {
    const vm = this;
    const $scope = vm;

    mnAlertsService.alerts
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((alerts) => {
        this.setState({alerts});
      });

    vm.closeAlert = mnAlertsService.removeItem;

    new mnEtagPoller($scope, function (previous) {
      return mnPoolDefault.get({
        etag: previous ? previous.etag : "",
        waitChange: 10000
      }, {group: "global"});
    }, true)
    .subscribe(function (resp, previous) {

      if (previous && (resp.thisNode.clusterCompatibility !=
                        previous.thisNode.clusterCompatibility)) {
        window.location.reload();
      }

      MnAdminService.stream.getPoolsDefault.next(resp);

      if (!_.isEqual(resp, previous)) {
        MnHelperReactService.rootScopeEmitter.emit('mnPoolDefaultChanged');
      }

      if (Number(localStorage.getItem("uiSessionTimeout")) !== (resp.uiSessionTimeout * 1000)) {
        MnHelperReactService.rootScopeEmitter.emit('newSessionTimeout', resp.uiSessionTimeout);
      }

      // vm.tabName = resp.clusterName;

      if (previous && !_.isEqual(resp.nodes, previous.nodes)) {
        MnHelperReactService.rootScopeEmitter.emit('nodesChanged', [resp.nodes, previous.nodes]);
      }

      if (previous && previous.buckets.uri !== resp.buckets.uri) {
        MnHelperReactService.rootScopeEmitter.emit('reloadBucketStats');
      }

      if (previous && previous.trustedCAsURI !== resp.trustedCAsURI) {
        MnHelperReactService.rootScopeEmitter.emit('reloadGetPoolsDefaultTrustedCAs');
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

      if (previous && previous.checkPermissionsURI != resp.checkPermissionsURI) {
        MnHelperReactService.rootScopeEmitter.emit('reloadPermissions');
      }
    })
    .cycle();

  }
  render() {
    return (
      <ModalProvider>
        <div className="alert-wrapper fix-position-bl">
          <MnElementDepot name="alerts" />
          {this.state.alerts.map((alert, index) => (
            <div
              key={index}
              className={`animate-alert alert overflow-wrap overflow-hidden enable-ng-animation max-height-10 alert-${alert.type}`}>
              <p className="padding-1">
                <span className="margin-right-half margin-left-half max-height-4 overflow-y-auto inline padding-left-half padding-right-half permanent-scroll">
                  {alert.msg}
                </span>
              </p>
              {alert.type !== 'success' && (
                <a
                  onClick={() => this.closeAlert(alert)}
                  className="close">X</a>
              )}
            </div>
          ))}
        </div>
        <div className="main-content min-width-zero delayed-spinner expanded-spinner fixed-spinner width-12">
          {/* ng-class="{'mn-main-spinner-active': adminCtl.mainSpinnerCounter.value()}"
          mn-spinner="adminCtl.mainSpinnerCounter.value() */}
          <UIView className="width-12" autoscroll={false} />
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