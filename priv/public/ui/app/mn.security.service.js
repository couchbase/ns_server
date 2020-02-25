import {Injectable} from "/ui/web_modules/@angular/core.js";
import {HttpClient, HttpParams, HttpHeaders} from '/ui/web_modules/@angular/common/http.js';
import {BehaviorSubject} from '/ui/web_modules/rxjs.js';
import {switchMap, shareReplay} from '/ui/web_modules/rxjs/operators.js';
import {MnHttpRequest} from './mn.http.request.js';

export {MnSecurityService};

class MnSecurityService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient
  ]}

  constructor(http) {
    this.http = http;

    this.stream = {};

    this.stream.getSaslauthdAuth =
      (new BehaviorSubject()).pipe(
        switchMap(this.getSaslauthdAuth.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getCertificate =
      (new BehaviorSubject()).pipe(
        switchMap(this.getCertificate.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getLogRedaction =
      (new BehaviorSubject()).pipe(
        switchMap(this.getLogRedaction.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getClientCertAuth =
      (new BehaviorSubject()).pipe(
        switchMap(this.getClientCertAuth.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getAudit =
      (new BehaviorSubject()).pipe(
        switchMap(this.getAudit.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getAuditDescriptors =
      (new BehaviorSubject()).pipe(
        switchMap(this.getAuditDescriptors.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.postLogRedaction =
      new MnHttpRequest(this.postLogRedaction.bind(this))
      .addSuccess()
      .addError();

    this.stream.postSession =
      new MnHttpRequest(this.postSession.bind(this))
      .addSuccess()
      .addError();

    this.stream.postClientCertAuth =
      new MnHttpRequest(this.postClientCertAuth.bind(this))
      .addSuccess()
      .addError();

    this.stream.postAuditValidation =
      new MnHttpRequest(this.postAudit(true).bind(this))
      .addSuccess()
      .addError();

    this.stream.postAudit =
      new MnHttpRequest(this.postAudit(false).bind(this))
      .addSuccess()
      .addError();
  }

  postAudit(validate) {
    return (data) => {
      return this.http.post("/settings/audit", data, {
        params: new HttpParams().set("just_validate", validate ? 1 : 0)
      });
    }
  }

  postSession(data) {
    return this.http.post("/settings/security", data);
  }

  getAuditDescriptors() {
    return this.http.get("/settings/audit/descriptors");
  }

  getAudit() {
    return this.http.get("/settings/audit");
  }

  getSaslauthdAuth() {
    return this.http.get("/settings/saslauthdAuth");
  }

  getClientCertAuth() {
    return this.http.get("/settings/clientCertAuth");
  }

  postClientCertAuth(data) {
    return this.http.post("/settings/clientCertAuth", data[0], {
      headers: new HttpHeaders().set("isNotForm", data[1])
    });
  }

  getLogRedaction() {
    return this.http.get("/settings/logRedaction");
  }

  postLogRedaction(data) {
    return this.http.post("/settings/logRedaction", data);
  }

  getCertificate() {
    return this.http.get("/pools/default/certificate", {
      params: new HttpParams().set("extended", true)
    });
  }
}
