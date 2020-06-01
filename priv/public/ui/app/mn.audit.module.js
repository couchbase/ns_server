import {NgModule} from '/ui/web_modules/@angular/core.js';
import {UIRouterModule} from "/ui/web_modules/@uirouter/angular.js";
import {ReactiveFormsModule} from '/ui/web_modules/@angular/forms.js';
import {NgbModule} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {MnSharedModule} from './mn.shared.module.js';

import {MnPipesModule} from './mn.pipes.module.js';

import {MnAuditComponent} from './mn.audit.component.js';
import {MnAuditItemComponent} from './mn.audit.item.component.js';
import {MnSecurityService} from './mn.security.service.js';

let auditState = {
  url: '/audit',
  name: "app.admin.security.audit",
  data: {
    enterprise: true
  },
  component: MnAuditComponent
};

export {MnAuditModule};

class MnAuditModule {
  static get annotations() { return [
    new NgModule({
      entryComponents: [
      ],
      declarations: [
        MnAuditComponent,
        MnAuditItemComponent
      ],
      imports: [
        MnPipesModule,
        ReactiveFormsModule,
        MnSharedModule,
        NgbModule,
        UIRouterModule.forChild({ states: [auditState] })
      ],
      providers: [
        MnSecurityService
      ]
    })
  ]}
}
