import { MnAppComponent } from './mn.app.component.js';
import { MnAppService } from './mn.app.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { mnAppImports } from './mn.app.imports.js';
import { MnHttpInterceptor } from './mn.http.interceptor.js';
import { MnExceptionHandlerService } from './mn.exception.handler.service.js';
import { NgModule, ErrorHandler} from '../web_modules/@angular/core.js';
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
        MnAppService,
        MnPoolsService,
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
  ]

  static parameters = [
    MnAppService,
    ErrorHandler
  ]

  constructor(mnAppService, mnExceptionHandlerService) {
    mnExceptionHandlerService.stream.appException
      .subscribe(mnExceptionHandlerService.send.bind(mnExceptionHandlerService));
    // setTimeout(function () {a}, 1000)

  }
}
