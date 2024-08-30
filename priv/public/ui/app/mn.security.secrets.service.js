/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Injectable} from '@angular/core';
import {HttpClient, HttpHeaders } from '@angular/common/http';
import {switchMap, shareReplay} from 'rxjs/operators';
import {BehaviorSubject, combineLatest, timer} from 'rxjs';

import {MnHttpRequest} from './mn.http.request.js';
import {singletonGuard} from './mn.core.js';

export {MnSecuritySecretsService}

class MnSecuritySecretsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient
  ]}

  constructor(http) {
    singletonGuard(MnSecuritySecretsService);

    this.http = http;
    this.stream = {};
    // this.types = ['config', 'logs', 'audit'];
    this.types = ['config'];

    this.stream.updateSecretsList =
      new BehaviorSubject();

    this.stream.getSecrets =
      combineLatest(timer(0, 10000),
                    this.stream.updateSecretsList)
      .pipe(switchMap(this.getSecrets.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getEncryptionAtRest =
      (new BehaviorSubject())
      .pipe(switchMap(this.getEncryptionAtRest.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.stream.deleteSecrets =
      new MnHttpRequest(this.deleteSecret.bind(this))
      .addSuccess()
      .addError();

    this.stream.postSecret =
      new MnHttpRequest(this.postSecret.bind(this))
      .addSuccess()
      .addError();

    this.stream.postRotateSecret =
      new MnHttpRequest(this.postRotateSecret.bind(this))
      .addSuccess()
      .addError();

    this.stream.putSecret =
      new MnHttpRequest(this.putSecret.bind(this))
      .addSuccess()
      .addError();

    this.stream.postEncryptionAtRest =
      new MnHttpRequest(this.postEncryptionAtRest.bind(this))
      .addSuccess()
      .addError();

    this.stream.postDropAtRestKeys =
      new MnHttpRequest(this.postDropAtRestKeys.bind(this))
      .addSuccess()
      .addError();

    this.types.forEach(type => {
      this.stream[type +'PostDropAtRestKeys'] =
        new MnHttpRequest(this.postDropAtRestKeys.bind(this)(type))
        .addSuccess()
        .addError();
    });
  }

  getSecrets() {
    return this.http.get('/settings/secrets');
  }

  postSecret([params]) {
    return this.http.post('/settings/secrets', params, { headers: new HttpHeaders().set("isNotForm", true) });
  }

  deleteSecret(id) {
    return this.http.delete('/settings/secrets/' + encodeURIComponent(id));
  }

  putSecret([params, id]) {
    return this.http.put('/settings/secrets/' + encodeURIComponent(id), params, { headers: new HttpHeaders().set("isNotForm", true) });
  }

  getEncryptionAtRest() {
    return this.http.get('/settings/security/encryptionAtRest');
  }

  postEncryptionAtRest(params) {
    return this.http.post('/settings/security/encryptionAtRest', params, { headers: new HttpHeaders().set("isNotForm", true) });
  }

  postRotateSecret(id) {
    return this.http.post('/controller/rotateSecret/' + encodeURIComponent(id));
  }

  postDropAtRestKeys(type) {
    return () => this.http.post('/controller/dropEncryptionAtRestKeys/' + encodeURIComponent(type));
  }
}
