var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnStorageMode =
  (function (Rx) {
    "use strict";

    MnStorageMode.annotations = [
      new ng.core.Component({
        selector: "mn-storage-mode",
        templateUrl: "app-new/mn-storage-mode.html",
        inputs: [
          "control",
          "indexFlagChanges",
          "permissionsIndexWrite",
          "isAtLeast50"
        ]
      })
    ];

    MnStorageMode.parameters = [
      mn.services.MnWizard,
      mn.services.MnPools
    ];

    MnStorageMode.prototype.ngOnInit = ngOnInit;
    MnStorageMode.prototype.ngOnDestroy = ngOnDestroy;

    return MnStorageMode;

    function ngOnDestroy() {
      this.destroy.next();
      this.destroy.complete();
    }

    function ngOnInit() {
      var isNotEnterprise =
          this.isEnterprise.pipe(Rx.operators.map(mn.helper.invert));

      var isFirstValueForestDB =
          this.control.valueChanges.pipe(
            Rx.operators.first(),
            Rx.operators.map(function (v) {
              return v === 'forestdb'
            })
          );

      this.showForestDB =
        Rx.combineLatest(
          isNotEnterprise,
          isFirstValueForestDB
        )
        .pipe(Rx.operators.map(_.curry(_.some)(_, Boolean)));

      this.showPlasma =
        Rx.combineLatest(
          this.isEnterprise,
          this.isAtLeast50 || Rx.of(true)
        )
        .pipe(Rx.operators.map(_.curry(_.every)(_, Boolean)));

      Rx.combineLatest(
        isNotEnterprise,
        (this.indexFlagChanges || Rx.of(true)).pipe(Rx.operators.map(mn.helper.invert)),
        (this.permissionsIndexWrite || Rx.of(true)).pipe(Rx.operators.map(mn.helper.invert))
      ).pipe(
        Rx.operators.map(_.curry(_.some)(_, Boolean)),
        Rx.operators.takeUntil(this.destroy)
      ).subscribe(doDisableControl.bind(this));
    }

    function doDisableControl(value) {
      this.control[value ? "disable" : "enable"]();
    }

    function MnStorageMode(mnWizardService, mnPoolsService) {
      this.destroy = new Rx.Subject();
      this.indexesHttp = mnWizardService.stream.indexesHttp;
      this.isEnterprise = mnPoolsService.stream.isEnterprise;
    }

  })(window.rxjs);
