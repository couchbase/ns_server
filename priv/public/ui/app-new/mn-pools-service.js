var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnPools = (function (Rx) {
  "use strict";

  var launchID =  (new Date()).valueOf() + '-' + ((Math.random() * 65536) >> 0);

  MnPoolsService.annotations = [
    new ng.core.Injectable()
  ];

  MnPoolsService.parameters = [
    ng.common.http.HttpClient,
    mn.pipes.MnParseVersion
  ];

  MnPoolsService.prototype.get = get;

  return MnPoolsService;

  function MnPoolsService(http, mnParseVersionPipe) {
    this.http = http;
    this.stream = {};

    this.stream.getSuccess =
      (new Rx.BehaviorSubject())
      .pipe(
        Rx.operators.switchMap(this.get.bind(this)),
        Rx.operators.multicast(function () {return new Rx.ReplaySubject(1);}),Rx.operators.refCount()
      );

    this.stream.isEnterprise =
      this.stream.getSuccess.pipe(Rx.operators.pluck("isEnterprise"));

    this.stream.implementationVersion =
      this.stream.getSuccess.pipe(Rx.operators.pluck("implementationVersion"));

    this.stream.majorMinorVersion =
      this.stream.implementationVersion.pipe(
        Rx.operators.map(mnParseVersionPipe.transform.bind(mnParseVersionPipe)),
        Rx.operators.map(function (rv) {
          return rv[0].split('.').splice(0,2).join('.');
        })
      );
  }

  function get(mnHttpParams) {
    return this.http.get('/pools').pipe(
      Rx.operators.map(function (pools) {
        pools.isInitialized = !!pools.pools.length;
        pools.launchID = pools.uuid + '-' + launchID;
        return pools;
      })
    );
  }
})(window.rxjs);
