import { BrowserModule } from '../web_modules/@angular/platform-browser.js';
import { HttpClientModule } from '../web_modules/@angular/common/http.js';
import { UIRouterModule, UIView } from '../web_modules/@uirouter/angular.js';
import { MnAppComponent } from './mn.app.component.js';

let mnAppState = {
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

export let mnAppImports = [
  BrowserModule,
  HttpClientModule,
  UIRouterModule.forRoot({
    states: [mnAppState],
    useHash: true
  })
];
