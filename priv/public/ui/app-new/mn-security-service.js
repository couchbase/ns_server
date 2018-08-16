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

  return MnSecurityService;

  function MnSecurityService(http) {
    this.http = http;

    this.stream = {};

    this.stream.getSaslauthdAuth =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getSaslauthdAuth.bind(this)),
        Rx.operators.shareReplay(1)
      );

    this.stream.getDefaultCertificate =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getDefaultCertificate.bind(this)),
        Rx.operators.shareReplay(1)
      );
  }

  function getSaslauthdAuth() {
    return this.http.get("/settings/saslauthdAuth");
  }

  function getDefaultCertificate() {
    return this.http.get("/pools/default/certificate", {
      params: new ng.common.http.HttpParams().set("extended", true)
    });
  }

})(window.rxjs);
