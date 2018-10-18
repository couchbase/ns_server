var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnAdmin = (function (Rx) {
  "use strict";

  // counterpart of ns_heart:effective_cluster_compat_version/0
  function encodeCompatVersion(major, minor) {
    return (major < 2) ? 1 : major * 0x10000 + minor;
  }

  function getPoolsDefaultInterval(state) {
    return state.to().name === "app.admin.overview" ? 3000 : 10000;
  }

  //TODO chech that the streams do not contain privat info after logout
  MnAdminService.annotations = [
    new ng.core.Injectable()
  ];

  MnAdminService.parameters = [
    mn.services.MnHelper,
    window['@uirouter/angular'].UIRouter,
    ng.common.http.HttpClient,
    mn.pipes.MnPrettyVersion
  ];

  MnAdminService.prototype.getVersion = getVersion;
  MnAdminService.prototype.getPoolsDefault = getPoolsDefault;
  MnAdminService.prototype.getWhoami = getWhoami;
  MnAdminService.prototype.postPoolsDefault = postPoolsDefault;

  return MnAdminService;

  function MnAdminService(mnHelperService, uiRouter, http, mnPrettyVersionPipe) {
    this.stream = {};
    this.http = http;
    this.stream.etag = new Rx.BehaviorSubject();

    this.stream.enableInternalSettings =
      uiRouter.globals.params$.pipe(Rx.operators.pluck("enableInternalSettings"));

    this.stream.whomi =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getWhoami.bind(this)),
        Rx.operators.multicast(function () {return new Rx.ReplaySubject(1);}),Rx.operators.refCount()
      );

    this.stream.getPoolsDefault =
      Rx.combineLatest(this.stream.etag,
                       uiRouter.globals.success$.pipe(Rx.operators.map(getPoolsDefaultInterval),
                                                      Rx.operators.distinctUntilChanged()))
      .pipe(Rx.operators.switchMap(this.getPoolsDefault.bind(this)),
            Rx.operators.multicast(function () {return new Rx.ReplaySubject(1);}),Rx.operators.refCount());

    this.stream.isRebalancing =
      this.stream.getPoolsDefault.pipe(
        Rx.operators.map(R.pipe(R.propEq('rebalanceStatus', 'none'), R.not)));

    this.stream.maxBucketCount =
      this.stream.getPoolsDefault.pipe(Rx.operators.pluck("maxBucketCount"));

    this.stream.uiSessionTimeout =
      this.stream.getPoolsDefault.pipe(Rx.operators.pluck("uiSessionTimeout"),
                                       Rx.operators.distinctUntilChanged());

    this.stream.ldapEnabled =
      this.stream.getPoolsDefault.pipe(Rx.operators.pluck("ldapEnabled"),
                                       Rx.operators.distinctUntilChanged(),
                                       Rx.operators.multicast(function () {return new Rx.ReplaySubject(1);}),Rx.operators.refCount());

    this.stream.implementationVersion =
      (new Rx.BehaviorSubject()).pipe(Rx.operators.switchMap(this.getVersion.bind(this)),
                                      Rx.operators.pluck("implementationVersion"),
                                      Rx.operators.multicast(function () {return new Rx.ReplaySubject(1);}),Rx.operators.refCount());

    this.stream.prettyVersion =
      this.stream.implementationVersion.pipe(
        Rx.operators.map(mnPrettyVersionPipe.transform.bind(mnPrettyVersionPipe)));

    this.stream.thisNode =
      this.stream.getPoolsDefault.pipe(Rx.operators.pluck("nodes"),
                                       Rx.operators.map(R.find(R.propEq('thisNode', true))));

    this.stream.memoryQuotas =
      this.stream.getPoolsDefault.pipe(
        Rx.operators.map(mnHelperService.pluckMemoryQuotas.bind(mnHelperService)));

    this.stream.clusterName =
      this.stream.getPoolsDefault.pipe(Rx.operators.pluck("clusterName"));

    this.stream.compatVersion51 =
      this.stream.thisNode.pipe(mnHelperService.compatVersionPipe(encodeCompatVersion(5, 1)));
    this.stream.compatVersion55 =
      this.stream.thisNode.pipe(mnHelperService.compatVersionPipe(encodeCompatVersion(5, 5)));

    this.stream.postPoolsDefault =
      new mn.core.MnPostHttp(this.postPoolsDefault.bind(this)).addSuccess().addError();

    this.stream.activateNodes =
      this.stream.getPoolsDefault.pipe(Rx.operators.pluck("nodes"),
                                       Rx.operators.map(
                                         R.filter(R.propEq('clusterMembership', 'active'))));

    this.stream.activateKvNodes =
      this.stream.activateNodes.pipe(Rx.operators.map(R.filter(R.pipe(R.path(["services"]),
                                                                      R.contains("kv")))));

  }

  function getVersion() {
    return this.http.get("/versions");
  }

  function getWhoami() {
    return this.http.get('/whoami');
  }

  function getPoolsDefault(params) {
    return this.http.get('/pools/default', {
      params: new ng.common.http.HttpParams()
        .set('waitChange', params[1])
        .set('etag', params[0] || "")
    });
  }

  function postPoolsDefault(data) {
    return this.http.post('/pools/default', data[0], {
      params: new ng.common.http.HttpParams()
        .set("just_validate", data[1] ? 1 : 0)
    });
  }

})(window.rxjs);
