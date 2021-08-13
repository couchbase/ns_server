/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {NgModule} from '../web_modules/@angular/core.js';

import {ReactiveFormsModule} from '../web_modules/@angular/forms.js';
import {HttpClientJsonpModule} from '../web_modules/@angular/common/http.js';
import {CommonModule} from '../web_modules/@angular/common.js';
import {NgbModule} from '../web_modules/@ng-bootstrap/ng-bootstrap.js';

import {MnWizardComponent} from './mn.wizard.component.js';
import {MnWizardWelcomeComponent} from './mn.wizard.welcome.component.js';
import {MnWizardSetupNewClusterComponent} from './mn.wizard.setup.new.cluster.component.js';
import {MnWizardNewClusterConfigComponent} from './mn.wizard.new.cluster.config.component.js';
import {MnWizardTermsAndConditionsComponent} from './mn.wizard.terms.and.conditions.component.js';
import {MnWizardJoinClusterComponent} from './mn.wizard.join.cluster.component.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnAuthService} from './mn.auth.service.js';
import {MnSharedModule} from './mn.shared.module.js';
import {MnPipesModule} from './mn.pipes.module.js';
import {HttpClientModule} from '../web_modules/@angular/common/http.js';
import {UIRouterModule} from '../web_modules/@uirouter/angular.js';
import {UIRouterUpgradeModule} from '../web_modules/@uirouter/angular-hybrid.js';

import {MnNodeStorageConfigComponent} from './mn.node.storage.config.component.js';
import {MnHostnameConfigComponent} from './mn.hostname.config.component.js';
import {MnServicesConfigComponent} from './mn.services.config.component.js';
import {MnStorageModeComponent} from './mn.storage.mode.component.js';
import {MnPathFieldComponent} from './mn.path.field.component.js';

import {HTTP_INTERCEPTORS} from '../web_modules/@angular/common/http.js';
import {MnHttpInterceptor} from './mn.http.interceptor.js';

let states = [{
  name: 'app.wizard',
  abstract: true,
  component: MnWizardComponent
}, {
  name: 'app.wizard.welcome',
  component: MnWizardWelcomeComponent
}, {
  name: "app.wizard.setupNewCluster",
  component: MnWizardSetupNewClusterComponent
}, {
  name: 'app.wizard.joinCluster',
  component: MnWizardJoinClusterComponent
}, {
  name:'app.wizard.termsAndConditions',
  component: MnWizardTermsAndConditionsComponent
}, {
  name: 'app.wizard.clusterConfiguration',
  component: MnWizardNewClusterConfigComponent
}];



export {MnWizardModule};

class MnWizardModule {
  static get annotations() { return [
    new NgModule({
      declarations: [
        MnNodeStorageConfigComponent,
        MnHostnameConfigComponent,
        MnServicesConfigComponent,
        MnStorageModeComponent,
        MnPathFieldComponent,

        MnWizardComponent,
        MnWizardWelcomeComponent,
        MnWizardNewClusterConfigComponent,
        MnWizardSetupNewClusterComponent,
        MnWizardTermsAndConditionsComponent,
        MnWizardJoinClusterComponent
      ],
      providers: [
        MnWizardService,
        MnAuthService,
        {
          provide: HTTP_INTERCEPTORS,
          useClass: MnHttpInterceptor,
          multi: true
        }
      ],
      imports: [
        UIRouterUpgradeModule.forChild({
          states: states
        }),
        NgbModule,
        UIRouterModule,
        CommonModule,
        ReactiveFormsModule,
        MnSharedModule,
        MnPipesModule,
        HttpClientModule,
        HttpClientJsonpModule
      ]
    })
  ]}
}
