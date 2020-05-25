import {NgModule} from '/ui/web_modules/@angular/core.js';
import {UIRouterModule} from "/ui/web_modules/@uirouter/angular.js";
import {MnSharedModule} from './mn.shared.module.js';
import {ReactiveFormsModule} from '/ui/web_modules/@angular/forms.js';
import {NgbModule} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';

import {MnSessionComponent} from './mn.session.component.js';
import {MnSessionService} from './mn.session.service.js';
import {MnBucketsService} from './mn.buckets.service.js';

let sessionState = {
  url: '/session',
  name: "app.admin.security.session",
  component: MnSessionComponent,
  data: {
    permissions: "cluster.admin.security.read"
  }
};

export {MnSessionModule};

class MnSessionModule {
  static get annotations() { return [
    new NgModule({
      entryComponents: [
      ],
      declarations: [
        MnSessionComponent
      ],
      imports: [
        NgbModule,
        ReactiveFormsModule,
        MnSharedModule,
        UIRouterModule.forChild({ states: [sessionState] })
      ],
      providers: [
        MnSessionService,
        MnBucketsService
      ]
    })
  ]}
}
