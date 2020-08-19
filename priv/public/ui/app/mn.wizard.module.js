import {NgModule} from '/ui/web_modules/@angular/core.js';

import {ReactiveFormsModule} from '/ui/web_modules/@angular/forms.js';
import {HttpClientJsonpModule} from '/ui/web_modules/@angular/common/http.js';
import {CommonModule} from '/ui/web_modules/@angular/common.js';
import {MnWizardComponent} from './mn.wizard.component.js';
import {MnWelcomeComponent} from './mn.welcome.component.js';
import {MnSetupNewClusterComponent} from './mn.setup.new.cluster.component.js';
import {MnNewClusterConfigComponent} from './mn.new.cluster.config.component.js';
import {MnTermsAndConditionsComponent} from './mn.terms.and.conditions.component.js';
import {MnJoinClusterComponent} from './mn.join.cluster.component.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnAuthService} from './mn.auth.service.js';
import {MnSharedModule} from './mn.shared.module.js';
import {MnPipesModule} from './mn.pipes.module.js';
import {HttpClientModule} from '/ui/web_modules/@angular/common/http.js';
import {UpgradeModule} from '/ui/web_modules/@angular/upgrade/static.js';
import {UIRouterModule} from '/ui/web_modules/@uirouter/angular.js';
import {UIRouterUpgradeModule} from '/ui/web_modules/@uirouter/angular-hybrid.js';

import {MnNodeStorageConfigComponent} from './mn.node.storage.config.component.js';
import {MnHostnameConfigComponent} from './mn.hostname.config.component.js';
import {MnServicesConfigComponent} from './mn.services.config.component.js';
import {MnStorageModeComponent} from './mn.storage.mode.component.js';
import {MnPathFieldComponent} from './mn.path.field.component.js';

import {MnAdminService} from './mn.admin.service.js';
import {MnPoolsService} from './mn.pools.service.js';

import {HTTP_INTERCEPTORS} from '/ui/web_modules/@angular/common/http.js';
import {MnHttpInterceptor} from './mn.http.interceptor.js';

let states = [{
  name: 'app.wizard',
  abstract: true,
  component: MnWizardComponent
}, {
  name: 'app.wizard.welcome',
  component: MnWelcomeComponent
}, {
  name: "app.wizard.setupNewCluster",
  component: MnSetupNewClusterComponent
}, {
  name: 'app.wizard.joinCluster',
  component: MnJoinClusterComponent
}, {
  name:'app.wizard.termsAndConditions',
  component: MnTermsAndConditionsComponent
}, {
  name: 'app.wizard.clusterConfiguration',
  component: MnNewClusterConfigComponent
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
        MnWelcomeComponent,
        MnNewClusterConfigComponent,
        MnSetupNewClusterComponent,
        MnTermsAndConditionsComponent,
        MnJoinClusterComponent
      ],
      providers: [
        MnWizardService,
        MnPoolsService,
        MnAdminService,
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
