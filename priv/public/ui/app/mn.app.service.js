import {Injectable} from "../web_modules/@angular/core.js";
import {BehaviorSubject, Subject} from "../web_modules/rxjs.js";
import {filter} from "../web_modules/rxjs/operators.js";
import {HttpErrorResponse, HttpClient} from '../web_modules/@angular/common/http.js';

export {MnAppService};

class MnAppService {
  static annotations = [
    new Injectable()
  ]

  constructor() {
    this.stream = {};
    this.stream.loading = new BehaviorSubject(false);
    this.stream.httpResponse = new Subject();
    this.stream.pageNotFound = new Subject();
    this.stream.http401 =
      this.stream.httpResponse.pipe(filter(function (rv) {
        //rejection.config.url !== "/controller/changePassword"
        //$injector.get('mnLostConnectionService').getState().isActivated
        return (rv instanceof HttpErrorResponse) &&
          (rv.status === 401) && !rv.headers.get("ignore-401");
      }));
  }
}
