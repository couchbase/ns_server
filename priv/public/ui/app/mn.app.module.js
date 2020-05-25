import app from "./app.js";
import { ajsUpgradedProviders } from '/ui/app/ajs.upgraded.providers.js';
import { MnAppComponent } from './mn.app.component.js';
import { MnAppService } from './mn.app.service.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnAdminService } from './mn.admin.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnSecurityService } from './mn.security.service.js';
import { mnAppImports } from './mn.app.imports.js';
import { MnFormService } from './mn.form.service.js';
import { MnHttpInterceptor } from './mn.http.interceptor.js';
import { MnExceptionHandlerService } from './mn.exception.handler.service.js';
import { NgModule, ErrorHandler, APP_INITIALIZER} from '/ui/web_modules/@angular/core.js';
import { HTTP_INTERCEPTORS, HttpClient } from '/ui/web_modules/@angular/common/http.js';
import { UIView} from '/ui/web_modules/@uirouter/angular.js';
import { UpgradeModule } from '/ui/web_modules/@angular/upgrade/static.js';


export { MnAppModule };

class MnAppModule {
  static get annotations() { return [
    new NgModule({
      declarations: [
      ],
      entryComponents: [
      ],
      imports: mnAppImports,
      // bootstrap: [
      //   UIView
      // ],
      providers: [
        ...ajsUpgradedProviders,
        MnSecurityService,
        MnAppService,
        MnAdminService,
        MnPoolsService,
        MnFormService,
        MnHelperService,
        {
          provide: HTTP_INTERCEPTORS,
          useClass: MnHttpInterceptor,
          multi: true
        }, {
          provide: ErrorHandler,
          useClass: MnExceptionHandlerService
        }
      ]
    })
  ]}

  static get parameters() {return  [UpgradeModule]}

  ngDoBootstrap() {
    this.upgrade.bootstrap(document, [app], { strictDi: false });
  }

  constructor(upgrade) {
    this.upgrade = upgrade;
  }

}
