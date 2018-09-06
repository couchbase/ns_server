var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnAuditItem =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnAuditItem, mn.helper.MnEventableComponent);

    MnAuditItem.annotations = [
      new ng.core.Component({
        selector: "mn-audit-item",
        templateUrl: "app-new/mn-audit-item.html",
        inputs: [
          "auditForm",
          "descriptors",
          "moduleName"
        ],
        // changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnAuditItem.parameters = [
      // mn.services.MnAdmin,
      // mn.services.MnPermissions
      // mn.services.MnTasks,
      // window['@uirouter/angular'].UIRouter,
    ];

    MnAuditItem.prototype.ngOnInit = ngOnInit;
    MnAuditItem.prototype.mapNames = mapNames;
    MnAuditItem.prototype.generateForm = generateForm;
    MnAuditItem.prototype.doToggleAll = doToggleAll;
    MnAuditItem.prototype.setToggleAllValue = setToggleAllValue;
    MnAuditItem.prototype.maybeDisableToggleAll = maybeDisableToggleAll;

    return MnAuditItem;

    function MnAuditItem(mnPermissionsService, mnTasksService, uiRouter) {
      mn.helper.MnEventableComponent.call(this);

      this.onToggleClick = new Rx.Subject();
      this.toggleSection =
        this.onToggleClick
        .pipe(Rx.operators.scan(mn.helper.invert, false),
              Rx.operators.multicast(mn.helper.createReplaySubject),
              Rx.operators.refCount());

    }

    function ngOnInit() {
      this.auditForm.get()
      this.formHelper = new ng.forms.FormGroup({
        toggleAll: new ng.forms.FormControl()
      });
      this.thisDescriptors = this.descriptors.pipe(Rx.operators.pluck(this.moduleName));
      this.thisDescriptors
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.generateForm.bind(this));

      var thisModuleGroup = this.auditForm.get("descriptors").get(this.moduleName);
      var auditdEnabledCtrl = this.auditForm.get("auditdEnabled");

      this.thisModuleChanges =
        thisModuleGroup.valueChanges.pipe(Rx.operators.startWith(thisModuleGroup.value));

      this.isAuditEnabled =
        auditdEnabledCtrl.valueChanges.pipe(Rx.operators.startWith(auditdEnabledCtrl.value));

      this.isAuditEnabled
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeDisableToggleAll.bind(this));

      this.isThereEnabledField =
        this.thisModuleChanges.pipe(
          Rx.operators.map(function (a) {
            return Object.values(a).includes(true);
          }),
          Rx.operators.multicast(mn.helper.createReplaySubject),
          Rx.operators.refCount()
        );

      this.thisModuleChanges.pipe(
        Rx.operators.map(function (a) {
          return Object.values(a).every(Boolean);
        }),
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(this.setToggleAllValue.bind(this));

      this.formHelper.get("toggleAll").valueChanges
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.doToggleAll.bind(this));


    }
    function maybeDisableToggleAll(value) {
      var method = value ? "enable" : "disable";
      this.formHelper.get("toggleAll")[method]({onlySelf: true, emitEvent: false});
    }
    function setToggleAllValue(value) {
      this.formHelper.get("toggleAll").setValue(value, {emitEvent: false});
    }
    function doToggleAll(value) {
      var thisModule = this.auditForm.get("descriptors").get(this.moduleName);
      var ids = Object.keys(thisModule.value);
      thisModule.patchValue(ids.reduce(function (acc, key) {
        acc[key] = value;
        return acc;
      }, {}));
    }

    function generateForm(descriptors) {
      this.auditForm.get("descriptors")
        .addControl(this.moduleName, new ng.forms.FormGroup(
          descriptors.reduce(function (acc, item) {
            acc[item.id] = new ng.forms.FormControl(item.value)
            return acc;
          }, {})
        ));
    }

    function mapNames(name) {
      switch (name) {
      case "auditd":
        return "Audit";
      case "ns_server":
        return "Server";
      case "n1ql":
        return "Query and Index Service";
      case "eventing":
        return "Eventing Service";
      case "memcached":
        return "Data Service";
      case "xdcr":
        return name.toUpperCase();
      case "fts":
        return "Search Service";
      default:
        return name.charAt(0).toUpperCase() + name.substr(1).toLowerCase();
      }
    }

  })(window.rxjs);
