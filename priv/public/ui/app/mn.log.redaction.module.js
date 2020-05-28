import {NgModule} from '/ui/web_modules/@angular/core.js';
import {UIRouterModule} from "/ui/web_modules/@uirouter/angular.js";
import {MnSharedModule} from './mn.shared.module.js';
import {ReactiveFormsModule} from '/ui/web_modules/@angular/forms.js';
import {NgbModule} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';

import {MnLogRedactionComponent} from './mn.log.redaction.component.js';
import {MnSecurityService} from './mn.security.service.js';
import {MnBucketsService} from './mn.buckets.service.js';
import {MnFormService} from './mn.form.service.js';

let logRedactionState = {
  url: '/redaction',
  name: "app.admin.security.redaction",
  component: MnLogRedactionComponent,
  data: {
    compat: "atLeast55",
    enterprise: true
  }
};

export {MnLogRedactionModule};

class MnLogRedactionModule {
  static get annotations() { return [
    new NgModule({
      entryComponents: [
      ],
      declarations: [
        MnLogRedactionComponent
      ],
      imports: [
        NgbModule,
        ReactiveFormsModule,
        MnSharedModule,
        UIRouterModule.forChild({ states: [logRedactionState] })
      ],
      providers: [
        MnSecurityService,
        MnBucketsService
      ]
    })
  ]}
}
