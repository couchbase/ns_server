var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnSecurity = (function () {
  "use strict";

  MnSecurityService.annotations = [
    new ng.core.Injectable()
  ];

  MnSecurityService.parameters = [
    ng.common.http.HttpClient
  ];

  MnSecurityService.prototype.getSaslauthdAuth = getSaslauthdAuth;

  return MnSecurityService;

  function MnSecurityService(http) {
    this.http = http;

    this.stream = {};

    this.stream.getSaslauthdAuth =
      (new Rx.BehaviorSubject())
      .switchMap(this.getSaslauthdAuth.bind(this))
      .shareReplay(1);
  }

  function getSaslauthdAuth() {
    return this.http.get("/settings/saslauthdAuth");
  }

})();
