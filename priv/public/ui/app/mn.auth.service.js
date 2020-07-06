import { Injectable } from "/ui/web_modules/@angular/core.js";
import { HttpClient } from '/ui/web_modules/@angular/common/http.js';
import { map } from '/ui/web_modules/rxjs/operators.js';
import { MnHttpRequest } from './mn.http.request.js';

export { MnAuthService }

class MnAuthService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient
  ]}

  constructor(http) {
    this.http = http;
    this.stream = {};

    this.stream.postUILogin =
      new MnHttpRequest(this.postUILogin.bind(this))
      .addSuccess()
      .addError(map(rv => rv.status));

    // this.stream.postUILogout =
    //   new mn.core.MnPostHttp(this.postUILogout.bind(this));
  }

  whoami() {
    return this.http.get('/whoami');
  }

  postUILogin(user) {
    return this.http.post('/uilogin', user || {});
    // should be moved into app.admin alerts
    // we should say something like you are using cached vesrion, reload the tab
    // return that.mnPoolsService
    //   .get$
    //   .map(function (cachedPools, newPools) {

    // if (cachedPools.implementationVersion !== newPools.implementationVersion) {
    //   return {ok: false, status: 410};
    // } else {
    //   return resp;
    // }
    // });
  }

  postUILogout() {
    return this.http.post("/uilogout");
    // .then(function () {
    //     $window.location.reload();
    //   }, function () {
    //     $window.location.reload();
    //   });
  }
}
