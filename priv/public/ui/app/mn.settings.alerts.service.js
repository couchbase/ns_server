/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { Injectable } from "../web_modules/@angular/core.js";
import { HttpClient } from '../web_modules/@angular/common/http.js';
import { MnHttpRequest } from './mn.http.request.js';
import { switchMap, shareReplay } from '../web_modules/rxjs/operators.js';
import { BehaviorSubject } from '../web_modules/rxjs.js';

export { MnSettingsAlertsService }

class MnSettingsAlertsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient
  ]}

  constructor(http) {
    this.http = http;
    this.stream = {};

    this.stream.getAlerts =
      (new BehaviorSubject()).pipe(
        switchMap(this.getAlerts.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.saveAlerts =
      new MnHttpRequest(this.saveAlerts.bind(this))
      .addSuccess()
      .addError();

    this.stream.testMail =
      new MnHttpRequest(this.testMail.bind(this))
      .addSuccess()
      .addError();

  }

  getAlerts() {
    return this.http.get('/settings/alerts');
  }

  saveAlerts(params) {
    return this.http.post('/settings/alerts', params);
  }

  testMail(params) {
    return this.http.post('/settings/alerts/testEmail', params);
  }

}
