var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnAdmin = (function (Rx) {
  "use strict";

  var version50 = encodeCompatVersion(5, 0);
  var version55 = encodeCompatVersion(5, 5);

  // counterpart of ns_heart:effective_cluster_compat_version/0
  function encodeCompatVersion(major, minor) {
    if (major < 2) {
      return 1;
    }
    return major * 0x10000 + minor;
  }

  //TODO chech that the streams do not contain privat info after logout
  MnAdminService.annotations = [
    new ng.core.Injectable()
  ];

  MnAdminService.parameters = [
    window['@uirouter/angular'].UIRouter,
    ng.common.http.HttpClient,
    mn.pipes.MnPrettyVersion
  ];

  MnAdminService.prototype.getVersion = getVersion;
  MnAdminService.prototype.getPoolsDefault = getPoolsDefault;
  MnAdminService.prototype.getWhoami = getWhoami;
  MnAdminService.prototype.postPoolsDefault = postPoolsDefault;

  return MnAdminService;

  function MnAdminService(uiRouter, http, mnPrettyVersionPipe) {
    this.stream = {};
    this.http = http;
    this.stream.etag = new Rx.BehaviorSubject();
    this.stream.enableInternalSettings =
      uiRouter.globals.params$.pipe(
        Rx.operators.pluck("enableInternalSettings")
      );

    this.stream.whomi =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getWhoami.bind(this)),
        Rx.operators.shareReplay(1)
      );

    this.stream.getPoolsDefault =
      Rx.combineLatest(
        uiRouter.globals.success$.pipe(
          Rx.operators.map(function (state) {
            return state.to().name === "app.admin.overview" ? 3000 : 10000;
          }),
          Rx.operators.distinctUntilChanged()
        ),
        this.stream.etag
      ).pipe(
        Rx.operators.switchMap(this.getPoolsDefault.bind(this)),
        Rx.operators.shareReplay(1)
      );

    this.stream.isRebalancing =
      this.stream.getPoolsDefault.pipe(
        Rx.operators.map(function (rv) {
          return rv.rebalanceStatus !== "none";
        })
      );

    this.stream.maxBucketCount =
      this.stream.getPoolsDefault.pipe(
        Rx.operators.pluck("maxBucketCount")
      );

    this.stream.ldapEnabled =
      this.stream.getPoolsDefault.pipe(
        Rx.operators.pluck("ldapEnabled"),
        Rx.operators.distinctUntilChanged(),
        Rx.operators.shareReplay(1)
      );

    this.stream.implementationVersion =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getVersion.bind(this)),
        Rx.operators.pluck("implementationVersion"),
        Rx.operators.shareReplay(1)
      );

    this.stream.prettyVersion =
      this.stream.implementationVersion.pipe(
        Rx.operators.map(mnPrettyVersionPipe.transform.bind(mnPrettyVersionPipe))
      );

    this.stream.thisNode =
      this.stream.getPoolsDefault.pipe(
        Rx.operators.pluck("nodes"),
        Rx.operators.map(function (nodes) {
          return _.detect(nodes, "thisNode");
        })
      );

    this.stream.compatVersion =
      this.stream.thisNode.pipe(
        Rx.operators.map(function (thisNode) {
          var compat = thisNode.clusterCompatibility;
          return {
            atLeast50: compat >= version50,
            atLeast55: compat >= version55
          };
        })
      );

    this.stream.poolsDefaultHttp =
      new mn.helper.MnPostHttp(this.postPoolsDefault.bind(this))
      .addSuccess()
      .addError();

    this.stream.activateNodes =
      this.stream.getPoolsDefault.pipe(
        Rx.operators.pluck("nodes"),
        Rx.operators.map(function (nodes) {
          return nodes.filter(function (node) {
            return node.clusterMembership === 'active';
          });
        })
      );

    this.stream.activateKvNodes =
      this.stream.activateNodes.pipe(
        Rx.operators.map(function (nodes) {
          return nodes.filter(function (node) {
            return node.services.indexOf("kv") > -1;
          });
        })
      );

  }

  function getVersion() {
    return this.http.get("/versions");
  }

  function getPoolsDefault(params) {
    return this.http.get('/pools/default', {
      params: new ng.common.http.HttpParams()
        .set('waitChange', params[0])
        .set('etag', params[1] || "")
    });
  }

  function postPoolsDefault(data) {
    return this.http.post('/pools/default', data[0], {
      params: new ng.common.http.HttpParams().set("just_validate", data[1] ? 1 : 0)
    }).pipe(
      Rx.operators.catchError(mn.helper.errorToStream)
    );
  }

  function getWhoami() {
    return this.http.get('/whoami');
  }
})(window.rxjs);
