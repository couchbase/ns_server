import { Injectable } from '../web_modules/@angular/core.js';
import { MnAppService } from './mn.app.service.js';
import { HttpParams } from '../web_modules/@angular/common/http.js';
import { is } from '../web_modules/ramda.js';
import { throwError } from '../web_modules/rxjs.js';
import { tap, catchError } from '../web_modules/rxjs/operators.js';

export { MnHttpInterceptor };

class MnHttpInterceptor {
  static annotations = [
    new Injectable()
  ]

  static parameters = [
    MnAppService
  ]

  constructor(mnAppService) {
    this.httpResponse = mnAppService.stream.httpResponse;
  }

  intercept(req, next) {
    var mnReq = req.clone({
      setHeaders: {
        'invalid-auth-response': 'on',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'ns-server-ui': 'yes'
      }
    });

    var params;
    var headers;

    if ((req.method === 'POST' || req.method === 'PUT')) {
      if (!req.headers.get('isNotForm')) {
        if (is(Object, mnReq.body) && !Array.isArray(mnReq.body)) {
          params = new HttpParams({
            fromObject: mnReq.body
          });
        } else {
          params = mnReq.body;
        }
        mnReq = mnReq.clone({
          body: params,
          responseType: 'text',
          headers: mnReq.headers.set(
            'Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8')});
      }
      if (req.headers.has('isNotForm')) {
        headers = mnReq.headers.delete('isNotForm');
        mnReq = mnReq.clone({headers: headers, responseType: 'text'});
      }
    }

    return next
      .handle(mnReq).pipe(
        tap((event) => {
          this.httpResponse.next(event);
        }),
        catchError((event) => {
          this.httpResponse.next(event);
          return throwError(event);
        })
      );
  }
}
