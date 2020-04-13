import {BrowserModule} from '../web_modules/@angular/platform-browser.js';
import {HttpClientModule} from '../web_modules/@angular/common/http.js';
import {UIRouterModule, UIView} from '../web_modules/@uirouter/angular.js';
import {MnPipesModule} from './mn.pipes.module.js';
import {MnAppComponent} from './mn.app.component.js';
import {MnAuthComponent} from './mn.auth.component.js';
import {MnAuthModule} from './mn.auth.module.js';
import {UpgradeModule} from '/ui/web_modules/@angular/upgrade/static.js';
import {MnSharedModule} from './mn.shared.module.js';
import {MnWizardModule} from './mn.wizard.module.js';
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

let authState = {
  name: "app.auth",
  component: MnAuthComponent
}

export let mnAppImports = [
  ...Object.values(pluggableUIsModules),
  UpgradeModule,
  UIRouterModule,
  MnPipesModule,
  BrowserModule,
  HttpClientModule,
  MnAuthModule,
  MnWizardModule,
  MnSharedModule,
  UIRouterUpgradeModule
  // UIRouterModule.forRoot({
  //   states: [appState, authState],
  //   useHash: true,
  //   config: function mnRouterConfig(uiRouter) {
  //     uiRouter.urlRouter.deferIntercept();
  //   }
  // })
];
