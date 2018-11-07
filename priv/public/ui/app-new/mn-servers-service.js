var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnServers = (function (Rx) {
  "use strict";

  MnServersService.annotations = [
    new ng.core.Injectable()
  ];

  MnServersService.parameters = [
    mn.services.MnAdmin,
    ng.common.http.HttpClient,
    mn.services.MnHelper
  ];

  MnServersService.prototype.isStillEjected = isStillEjected;
  MnServersService.prototype.getNodes = getNodes;
  MnServersService.prototype.addToPendingEject = addToPendingEject;
  MnServersService.prototype.removePendingEject = removePendingEject;
  MnServersService.prototype.postRebalance = postRebalance;
  MnServersService.prototype.stopRebalance = stopRebalance;

  return MnServersService;

  function MnServersService(mnAdminService, http, mnHelperService) {
    this.http = http;
    this.stream = {};
    this.stream.ejectedNodesByUI = new Rx.BehaviorSubject({});
    this.stream.toggleFailoverWarning = new mnHelperService.createToggle();
    this.stream.postRebalance =
      new mn.core.MnPostHttp(this.postRebalance.bind(this)).addSuccess().addError();

    this.stream.stopRebalance =
      new mn.core.MnPostHttp(this.stopRebalance.bind(this)).addSuccess().addError();

    var getPoolsDefault = mnAdminService.stream.getPoolsDefault;
    this.stream.nodes = getPoolsDefault.pipe(Rx.operators.pluck("nodes"));

    this.stream.updateEjectedNodes =
      this.stream.nodes.pipe(Rx.operators.withLatestFrom(this.stream.ejectedNodesByUI),
                             Rx.operators.map(this.isStillEjected));

    this.stream.activeNodes =
      this.stream.nodes
      .pipe(Rx.operators.map(R.filter(R.propEq('clusterMembership', 'active'))),
            mn.core.rxOperatorsShareReplay(1));

    this.stream.notActiveNodes =
      this.stream.nodes
      .pipe(Rx.operators.map(R.filter(R.pipe(R.propEq('clusterMembership', 'active'), R.not))),
            mn.core.rxOperatorsShareReplay(1));

    this.stream.ejectedNodesLength =
      this.stream.ejectedNodesByUI.pipe(Rx.operators.map(R.pipe(R.keys, R.prop("length"))));

    var filterEjectedNodes =
        R.pipe(Rx.operators.map(function (source) {
          return source[0].filter(function (node) {
            return !source[1][node.otpNode];
          });
        }), mn.core.rxOperatorsShareReplay(1));

    this.stream.activeNodesWithoutEjected =
      Rx.combineLatest(
        this.stream.activeNodes,
        this.stream.ejectedNodesByUI
      ).pipe(filterEjectedNodes);

    this.stream.areAllPorts8091 =
      this.stream.nodes.pipe(Rx.operators.map(R.all(R.pipe(R.prop("hostname"),
                                                           R.test(/:8091$/)))),
                             mn.core.rxOperatorsShareReplay(1));

    mnHelperService.services.forEach(function (service) {
      this.stream[service + "ActiveNodes"] =
        this.stream.activeNodes.pipe(
          Rx.operators.map(R.filter(R.pipe(R.prop("services"), R.contains(service)))),
          mn.core.rxOperatorsShareReplay(1));
    }.bind(this));

    mnHelperService.services.forEach(function (service) {
      this.stream[service + "ActiveNodesWithoutEjected"] =
        Rx.combineLatest(
          this.stream[service + "ActiveNodes"],
          this.stream.ejectedNodesByUI
        ).pipe(filterEjectedNodes);
    }.bind(this));

    this.stream.isUnhealthyActiveNodesWithoutEjected =
      this.stream.activeNodesWithoutEjected
      .pipe(Rx.operators.map(R.pipe(R.find(R.propEq("status", "unhealthy")),
                                    Boolean)));

    this.humanReadableRebalanceErrorsPipe =
      Rx.operators.map(R.cond([
        [R.propEq('mismatch', 1), R.always("Could not Rebalance because the cluster configuration was modified by someone else.\nYou may want to verify the latest cluster configuration and, if necessary, please retry a Rebalance.")],
        [R.propEq('deltaRecoveryNotPossible', 1), R.always("Could not Rebalance because requested delta recovery is not possible. You probably added more nodes to the cluster or changed server groups configuration.")],
        [R.propEq('noKVNodesLeft', 1), R.always("Could not Rebalance out last kv node(s).")],
        [R.T, R.always("Request failed. Check logs.")]
      ]));
  }

  function isStillEjected(source) {
    return source[0].reduce(function (acc, node) {
      var ejected = source[1][node.otpNode];
      if (!!ejected &&
          ejected.clusterMembership == node.clusterMembership &&
          ejected.status == node.status) {
        acc[node.otpNode] = node;
      }
      return acc;
    }, {});
  }

  function postRebalance(source) {
    var pluck = R.pipe(R.pluck("otpNode"), R.join(","));
    return this.http
      .post("/controller/rebalance", {
        knownNodes: pluck(source[1]),
        ejectedNodes: R.pipe(R.values, pluck)(source[2])
      });
  }

  function stopRebalance(allowUnsafe) {
    return this.http.post('/controller/stopRebalance', {
      allowUnsafe: !!allowUnsafe
    }, {
      responseType: 'text'
    });
  }

  function getNodes(otpNode) {
    return this.http.get('/nodes/' + encodeURIComponent(otpNode));
  }

  function addToPendingEject(node) {
    var ejectedNodes = this.stream.ejectedNodesByUI.getValue();
    ejectedNodes[node.otpNode] = node;
    this.stream.ejectedNodesByUI.next(ejectedNodes);
  }

  function removePendingEject(node) {
    var ejectedNodes = this.stream.ejectedNodesByUI.getValue();
    delete ejectedNodes[node.otpNode];
    this.stream.ejectedNodesByUI.next(ejectedNodes);
  }

})(window.rxjs);
