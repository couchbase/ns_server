var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnSecurity = (function (Rx) {
  "use strict";

  MnSecurityService.annotations = [
    new ng.core.Injectable()
  ];

  MnSecurityService.parameters = [
    ng.common.http.HttpClient
  ];

  MnSecurityService.prototype.getSaslauthdAuth = getSaslauthdAuth;
  MnSecurityService.prototype.getDefaultCertificate = getDefaultCertificate;
  MnSecurityService.prototype.getLogRedaction = getLogRedaction;
  MnSecurityService.prototype.postLogRedaction = postLogRedaction;
  MnSecurityService.prototype.getClientCertAuth = getClientCertAuth;
  MnSecurityService.prototype.postClientCertAuth = postClientCertAuth;

  return MnSecurityService;

  function MnSecurityService(http) {
    this.http = http;

    this.stream = {};

    this.stream.getSaslauthdAuth =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getSaslauthdAuth.bind(this)),
        Rx.operators.multicast(mn.helper.createReplaySubject),
        Rx.operators.refCount()
      );

    this.stream.getDefaultCertificate =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getDefaultCertificate.bind(this)),
        Rx.operators.multicast(mn.helper.createReplaySubject),
        Rx.operators.refCount()
      );

    this.stream.getLogRedaction =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getLogRedaction.bind(this)),
        Rx.operators.multicast(mn.helper.createReplaySubject),
        Rx.operators.refCount()
      );

    this.stream.getClientCertAuth =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getClientCertAuth.bind(this)),
        Rx.operators.multicast(mn.helper.createReplaySubject),
        Rx.operators.refCount()
      );

    this.stream.postLogRedaction =
      new mn.helper.MnPostHttp(this.postLogRedaction.bind(this))
      .addSuccess()
      .addError();

    this.stream.postClientCertAuth =
      new mn.helper.MnPostHttp(this.postClientCertAuth.bind(this))
      .addSuccess()
      .addError();
  }

  function getSaslauthdAuth() {
    return this.http.get("/settings/saslauthdAuth");
  }

  function getClientCertAuth() {
    return this.http.get("/settings/clientCertAuth");
  }

  function postClientCertAuth(data) {
    return this.http.post("/settings/clientCertAuth", data[0], {
      headers: new ng.common.http.HttpHeaders().set("isNotForm", data[1])
    });
  }

  function getLogRedaction() {
    return this.http.get("/settings/logRedaction");
  }

  function postLogRedaction(data) {
    return this.http.post("/settings/logRedaction", data);
  }

  function getDefaultCertificate() {
    return this.http.get("/pools/default/certificate", {
      params: new ng.common.http.HttpParams().set("extended", true)
    });
  }

})(window.rxjs);
