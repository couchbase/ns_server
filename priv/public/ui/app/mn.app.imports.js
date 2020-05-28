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
  loadChildren: () => {
    return import('./mn.wizard.module.js').then(m => {
      return m.MnWizardModule;
    });
  }
};

let collectionsState = {
  name: 'app.admin.collections.**',
  url: '/collections',
  loadChildren: () => {
    return import('./mn.collections.module.js').then(m => {
      return m.MnCollectionsModule;
    });
  }
};

let sessionState = {
  name: 'app.admin.security.session.**',
  url: '/session',
  loadChildren: () => {
    return import('./mn.session.module.js').then(m => {
      return m.MnSessionModule;
    });
  }
};

let logRedactionState = {
  name: 'app.admin.security.redaction.**',
  url: '/redaction',
  loadChildren: () => {
    return import('./mn.log.redaction.module.js').then(m => {
      return m.MnLogRedactionModule;
    });
  }
};

let overviewState = {
  name: 'app.admin.overview.**',
  url: '/overview',
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_overview_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnOverview'});
    });
  }
};

let serversState = {
  name: 'app.admin.servers.**',
  url: '/servers',
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_servers_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnServers'});
    });
  }
};

let logsState = {
  name: 'app.admin.logs.**',
  url: '/logs',
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_logs_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnLogs'});
    });
  }
};

let groupsState = {
  name: 'app.admin.groups.**',
  url: '/groups',
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_groups_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnGroups'});
    });
  }
};

let bucketsState = {
  name: 'app.admin.buckets.**',
  url: '/buckets',
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_buckets_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnBuckets'});
    });
  }
};

let documentsState = {
  name: "app.admin.documents.**",
  url: "/documents",
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_documents_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnDocuments'});
    });
  }
};

let authState = {
  name: "app.auth.**",
  loadChildren: () => {
    return import('./mn.auth.module.js').then(m => {
      return m.MnAuthModule;
    });
  }
};

let gsiState = {
  name: "app.admin.gsi.**",
  url: "/index",
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_gsi_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnGsi'});
    });
  }
};

let viewsState = {
  name: "app.admin.views.**",
  url: "/views",
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_views_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnViews'});
    });
  }
};

let settingsState = {
  name: "app.admin.settings.**",
  url: "/settings",
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_settings_config.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnSettings'});
    });
  }
};

let securityState = {
  name: "app.admin.security.**",
  url: "/security",
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_security_config.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnSecurity'});
    });
  }
};

let xdcrState = {
  name: "app.admin.replications.**",
  url: "/replications",
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_xdcr_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnXDCR'});
    });
  }
};

export let mnAppImports = [
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
    states: [authState, wizardState, overviewState, serversState, bucketsState, logsState, groupsState, documentsState, gsiState, viewsState, settingsState, securityState, xdcrState, collectionsState, sessionState, logRedactionState]
  })
];
