var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnServersEjectDialog =
  (function (Rx) {
    "use strict";

    mn.core.extend(MnServersEjectDialog, mn.core.MnEventableComponent);

    MnServersEjectDialog.annotations = [
      new ng.core.Component({
        selector: "mn-servers-eject-dialog-component",
        templateUrl: "app-new/mn-servers-eject-dialog.html",
        inputs: [
          "nodeStream"
        ],
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnServersEjectDialog.parameters = [
      ngb.NgbActiveModal,
      mn.services.MnServers,
      mn.services.MnHelper,
      mn.services.MnPools,
      mn.services.MnGSI,
      mn.services.MnPermissions
    ];

    MnServersEjectDialog.prototype.ngOnInit = ngOnInit;

    return MnServersEjectDialog;

    function ngOnInit() {
      this.doEjectNode = new Rx.Subject();

      this.mnHelperService.services.forEach(function (service) {
        this[service + "IsLast"] =
          Rx.combineLatest(
            this.mnServersService.stream[service + "ActiveNodesWithoutEjected"]
              .pipe(Rx.operators.map(R.pipe(R.prop("length"), R.equals(1)))),
            this.nodeStream
              .pipe(Rx.operators.map(R.pipe(R.prop("services"), R.indexOf(service), R.lt(-1))))
          ).pipe(Rx.operators.map(R.all(R.equals(true))));
      }.bind(this));

      this.isKVNode =
        this.nodeStream.pipe(Rx.operators.map(R.pipe(R.prop("services"),
                                                     R.indexOf("kv"),
                                                     R.lt(-1))));
      this.doEjectNode
        .pipe(Rx.operators.withLatestFrom(this.nodeStream),
              Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(function (node) {
          this.mnServersService.addToPendingEject(node[1]);
          this.activeModal.close();
        }.bind(this));

      this.isThereIndex =
        this.getIndexStatus.pipe(Rx.operators.withLatestFrom(this.nodeStream),
                                 Rx.operators.map(function (source) {
                                   return source[0].indexes.find(function (index) {
                                     return index.hosts.includes(source[1].hostname);
                                   });
                                 }))
    }

    function MnServersEjectDialog(activeModal, mnServersService, mnHelperService, mnPoolsService, mnGSIService, mnPermissionsService) {
      mn.core.MnEventableComponent.call(this);

      this.activeModal = activeModal;
      this.mnServersService = mnServersService;
      this.mnHelperService = mnHelperService;
      this.isEnterprise = mnPoolsService.stream.isEnterprise;
      this.bucketAnyN1qlIndexRead =
        mnPermissionsService.createPermissionStream("n1ql.index!read", ".");
      this.getIndexStatus = mnGSIService.stream.getIndexStatus;
    }

  })(window.rxjs);
