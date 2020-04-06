import {CommonModule} from '/ui/web_modules/@angular/common.js';
import {BrowserModule} from '/ui/web_modules/@angular/platform-browser.js';
import {HttpClientModule} from '../web_modules/@angular/common/http.js';
import {UIRouterModule, UIView} from '../web_modules/@uirouter/angular.js';
import {MnPipesModule} from './mn.pipes.module.js';
import {MnAppComponent} from './mn.app.component.js';
import {MnAuthComponent} from './mn.auth.component.js';
import {UpgradeModule} from '/ui/web_modules/@angular/upgrade/static.js';
import {MnSharedModule} from './mn.shared.module.js';
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

let bucketsState = {
  name: 'app.admin.buckets.**',
  url: '/buckets',
  lazyLoad: ($transition$) => {
    return import('./mn_admin/mn_buckets_controller.js').then(m => {
      $transition$.injector().get('$ocLazyLoad').load({name: 'mnBuckets'});
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

export let mnAppImports = [
  ...Object.values(pluggableUIsModules),
  UpgradeModule,
  UIRouterModule,
  MnPipesModule,
  BrowserModule,
  CommonModule,
  HttpClientModule,
  MnSharedModule,
  UIRouterUpgradeModule.forRoot({
    states: [authState, wizardState, overviewState, serversState, bucketsState, logsState]
  })
];
