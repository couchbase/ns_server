var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnServers = (function (Rx) {
  "use strict";

  MnServersService.annotations = [
    new ng.core.Injectable()
  ];

  MnServersService.parameters = [
    mn.services.MnAdmin,
    ng.common.http.HttpClient
  ];

  MnServersService.prototype.isStillRejected = isStillRejected;
  MnServersService.prototype.getNodes = getNodes;

  return MnServersService;

  function MnServersService(mnAdminService, http) {
    this.http = http;
    this.stream = {};
    this.stream.ejectedNodesByUI = new Rx.BehaviorSubject({});

    var getPoolsDefault = mnAdminService.stream.getPoolsDefault;
    this.stream.nodes = getPoolsDefault.pipe(Rx.operators.pluck("nodes"));

    this.stream.activateNodes =
      this.stream.nodes
      .pipe(Rx.operators.map(R.filter(R.propEq('clusterMembership', 'active'))));

    //?
    this.stream.notActivateNodes =
      this.stream.nodes
      .pipe(Rx.operators.map(R.filter(R.pipe(R.propEq('clusterMembership', 'active'), R.not))));

    this.stream.ejectedNodes =
      this.stream.nodes
      .pipe(Rx.operators.withLatestFrom(this.stream.ejectedNodesByUI),
            Rx.operators.map(function (nodes) {
              return R.indexBy(R.prop('otpNode'),
                               nodes[0].filter(this.isStillRejected, nodes[1]))}.bind(this)));

    this.stream.ejectedNodesLength =
      this.stream.ejectedNodesByUI.pipe(Rx.operators.map(R.pipe(R.keys, R.prop("length"))));

    this.stream.activateNodesWithoutEjected =
      this.stream.activateNodes
      .pipe(Rx.operators.map(R.filter(R.pipe(R.prop("pendingEject"), R.not))));

    this.stream.activateKVNodesWithoutEjected =
      this.stream.activateNodes.pipe(Rx.operators.map(R.filter(R.allPass([
        R.pipe(R.prop("pendingEject"), R.not),
        R.pipe(R.prop("services"), R.contains("kv"))
      ]))));

    this.stream.areAllPorts8091 =
      this.stream.nodes.pipe(Rx.operators.map(R.all(R.pipe(R.prop("hostname"),
                                                           R.test(/:8091$/)))),
                             mn.core.rxOperatorsShareReplay(1));

    this.stream.activateKvNodes =
      this.stream.activateNodes.pipe(Rx.operators.map(R.filter(R.pipe(R.prop("services"),
                                                                      R.contains("kv")))));
    this.stream.isUnhealthyActiveNodesWithoutEjected =
      this.stream.activateNodesWithoutEjected
      .pipe(Rx.operators.map(R.pipe(R.find(R.propEq("status", "unhealthy")),
                                    Boolean)));
  }

  function getNodes(otpNode) {
    return this.http.get('/nodes/' + encodeURIComponent(otpNode));
  }

  function isStillRejected(node) {
    var rejected = this[node.otpNode];
    return !!rejected &&
      rejected.clusterMembership == node.clusterMembership &&
      rejected.status == node.status;
  }

})(window.rxjs);
