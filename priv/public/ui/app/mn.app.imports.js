/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {CommonModule} from '/ui/web_modules/@angular/common.js';
import {BrowserModule} from '/ui/web_modules/@angular/platform-browser.js';
import {HttpClientModule} from '../web_modules/@angular/common/http.js';
import {UIRouterModule, UIView} from '../web_modules/@uirouter/angular.js';
import {MnPipesModule} from './mn.pipes.module.js';
import {MnAppComponent} from './mn.app.component.js';
import {MnAuthComponent} from './mn.auth.component.js';
import {UpgradeModule} from '/ui/web_modules/@angular/upgrade/static.js';
import {MnSharedModule} from './mn.shared.module.js';
import {MnElementCraneModule} from './mn.element.crane.js';
import {UIRouterUpgradeModule} from '/ui/web_modules/@uirouter/angular-hybrid.js';
import * as pluggableUIsModules from '/ui/pluggable-uis.js';

import {MnKeyspaceSelectorModule} from './mn.keyspace.selector.module.js';


let appState = {
  name: 'app',
  url: '/?{enableInternalSettings:bool}&{disablePoorMansAlerts:bool}',
  component: MnAppComponent,
  params: {
    enableInternalSettings: {
      value: null,
      squash: true,
      dynamic: true
    },
    disablePoorMansAlerts: {
      value: null,
      squash: true,
      dynamic: true
    }
  },
  abstract: true
};

let wizardState = {
  name: 'app.wizard.**',
  loadChildren: () =>
    mnLazyload('./mn.wizard.module.js', 'MnWizardModule')
};

let collectionsState = {
  name: 'app.admin.collections.**',
  url: '/collections',
  loadChildren: () =>
    mnLazyload('./mn.collections.module.js', 'MnCollectionsModule')
};

let XDCRState = {
  name: 'app.admin.replications.**',
  url: '/replications',
  loadChildren: () =>
    mnLazyload('./mn.xdcr.module.js', "MnXDCRModule")
};

let sessionState = {
  name: 'app.admin.security.session.**',
  url: '/session',
  loadChildren: () =>
    mnLazyload('./mn.session.module.js', 'MnSessionModule')
};

let logRedactionState = {
  name: 'app.admin.security.redaction.**',
  url: '/redaction',
  loadChildren: () =>
    mnLazyload('./mn.security.log.redaction.module.js', 'MnSecurityLogRedactionModule')
};

let auditState = {
  name: 'app.admin.security.audit.**',
  url: '/audit',
  loadChildren: () =>
    mnLazyload('./mn.security.audit.module.js', 'MnSecurityAuditModule')
};

let overviewState = {
  name: 'app.admin.overview.**',
  url: '/overview',
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_overview_controller.js', 'mnOverview', $transition$)
};

let serversState = {
  name: 'app.admin.servers.**',
  url: '/servers',
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_servers_controller.js', 'mnServers', $transition$)
};

let logsState = {
  name: 'app.admin.logs.**',
  url: '/logs',
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_logs_controller.js', "mnLogs", $transition$)
};

let groupsState = {
  name: 'app.admin.groups.**',
  url: '/groups',
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_groups_controller.js', 'mnGroups', $transition$)
};

let bucketsState = {
  name: 'app.admin.buckets.**',
  url: '/buckets',
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_buckets_controller.js', 'mnBuckets', $transition$)
};

let documentsState = {
  name: "app.admin.documents.**",
  url: "/documents",
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_documents_controller.js', 'mnDocuments', $transition$)
};

let authState = {
  name: "app.auth.**",
  loadChildren: () =>
    mnLazyload('./mn.auth.module.js', 'MnAuthModule')
};

let gsiState = {
  name: "app.admin.gsi.**",
  url: "/index",
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_gsi_controller.js', 'mnGsi', $transition$)
};

let viewsState = {
  name: "app.admin.views.**",
  url: "/views",
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_views_controller.js', "mnViews", $transition$)
};

let settingsState = {
  name: "app.admin.settings.**",
  url: "/settings",
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_settings_config.js', "mnSettings", $transition$)
};

let securityState = {
  name: "app.admin.security.**",
  url: "/security",
  lazyLoad: ($transition$) =>
    mnLazyload('./mn_admin/mn_security_config.js', "mnSecurity", $transition$)
};

function rejectTransition() {
  return Promise.reject(new Error('Lazy loading has been suppressed by another transition'));
}

function mnLazyload(url, module, $transition$) {
  let initialHref = window.location.href;
  return import(url).then(m => {
    let postImportHref = window.location.href;
    if (initialHref === postImportHref) {
      if ($transition$) {
        return $transition$.injector().get('$ocLazyLoad').load({name: module}).then(loaded => {
          let postLoadHref = window.location.href;
          if (initialHref === postLoadHref) {
            return loaded;
          } else {
            return rejectTransition();
          }
        });
      } else {
        return m[module];
      }
    } else {
      return rejectTransition();
    }
  });
}

let mnAppImports = [
  ...Object.values(pluggableUIsModules),
  UpgradeModule,
  UIRouterModule,
  MnPipesModule,
  BrowserModule,
  CommonModule,
  HttpClientModule,
  MnSharedModule,
  MnElementCraneModule.forRoot(),
  UIRouterUpgradeModule.forRoot({
    states: [authState, wizardState, overviewState, serversState, bucketsState, logsState, groupsState, documentsState, gsiState, viewsState, settingsState, securityState, collectionsState, XDCRState, sessionState, logRedactionState, auditState]
  }),

  //downgradedModules
  MnKeyspaceSelectorModule
];

export {mnAppImports, mnLazyload};
