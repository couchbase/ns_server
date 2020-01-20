import { MnAppComponent } from './mn.app.component.js';
import { MnAppService } from './mn.app.service.js';
import { mnAppImports } from './mn.app.imports.js';
import { MnHttpInterceptor } from './mn.http.interceptor.js';
import { NgModule } from '../web_modules/@angular/core.js';
import { HTTP_INTERCEPTORS, HttpClient } from '../web_modules/@angular/common/http.js';
import { UIView } from '../web_modules/@uirouter/angular.js';

export { MnAppModule };

class MnAppModule {
  static annotations = [
    new NgModule({
      declarations: [
        MnAppComponent
      ],
      imports: mnAppImports,
      bootstrap: [
        UIView
      ],
      providers: [
        MnAppService, {
          provide: HTTP_INTERCEPTORS,
          useClass: MnHttpInterceptor,
          multi: true
        }
      ]
    })
  ]

  static parameters = [
    MnAppService,
    HttpClient
  ]

  constructor(mnAppService) {

  }
}
