/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Injectable} from "/ui/web_modules/@angular/core.js";
import {HttpClient} from '/ui/web_modules/@angular/common/http.js';
import {timer} from '/ui/web_modules/rxjs.js';
import {switchMap, shareReplay} from '/ui/web_modules/rxjs/operators.js';

export {MnLogsListService};

class MnLogsListService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient
  ]}

  constructor(http) {
    this.http = http;

    this.stream = {};

    this.stream.logs =
      timer(0, 10000).pipe(
        switchMap(this.getLogs.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));
  }

  getLogs() {
    return this.http.get('/logs');
  }
}
