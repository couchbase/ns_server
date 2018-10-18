var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnServicesConfig =
  (function (Rx) {
    "use strict";

    mn.core.extend(MnServicesConfig, mn.core.MnEventableComponent);

    MnServicesConfig.annotations = [
      new ng.core.Component({
        selector: "mn-services-config",
        templateUrl: "app-new/mn-services-config.html",
        inputs: [
          "group",
          "initDataStream"
        ],
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnServicesConfig.parameters = [
      mn.services.MnHelper,
      mn.services.MnAdmin,
      mn.services.MnPools
    ];

    MnServicesConfig.prototype.ngOnInit = ngOnInit;
    MnServicesConfig.prototype.validate = validate;
    MnServicesConfig.prototype.selectInitialFocus = selectInitialFocus;
    MnServicesConfig.prototype.calculateTotal = calculateTotal;
    MnServicesConfig.prototype.packQuotas = packQuotas;
    MnServicesConfig.prototype.getQuota= getQuota;
    MnServicesConfig.prototype.createToggleFieldStream = createToggleFieldStream;
    MnServicesConfig.prototype.toggleFields = toggleFields;
    MnServicesConfig.prototype.getFlag = getFlag;
    MnServicesConfig.prototype.getField = getField;

    return MnServicesConfig;

    function MnServicesConfig(mnHelperService, mnAdminService, mnPoolsService) {
      mn.core.MnEventableComponent.call(this);
      this.postPoolsDefault = mnAdminService.stream.postPoolsDefault;
      this.isEnterprise = mnPoolsService.stream.isEnterprise;
      this.quotaServices = mnHelperService.quotaServices;
      this.allServices = mnHelperService.services;
      this.getServiceName = mnHelperService.getServiceVisibleName;
      this.getServiceErrorName = mnHelperService.getServiceQuotaName;
    }

    function ngOnInit() {
      this.isWithFlag = !!this.group.get("flag");
      this.isWithField = !!this.group.get("field");
      if (!this.isWithField) {
        return;
      }
      this.focusFieldSubject = new Rx.BehaviorSubject(
        this.quotaServices.find(this.selectInitialFocus.bind(this))
      );
      if (this.isWithFlag && this.isWithField) {
        this.total = Rx
          .merge(this.group.valueChanges, this.initDataStream)
          .pipe(Rx.operators.map(this.calculateTotal.bind(this))
        );
      }
      if (this.isWithFlag) {
        this.quotaServices.forEach(this.createToggleFieldStream.bind(this))
      }

      this.group.valueChanges
        .pipe(Rx.operators.throttleTime(500, undefined, {leading: true, trailing: true}),
              Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.validate.bind(this));

      this.initDataStream
        .subscribe(function (memoryQuota) {
          this.group.get("field").patchValue(memoryQuota, {emitEvent: false});
        }.bind(this));
    }

    function selectInitialFocus(service) {
      return this.group.value.field[service];
    }

    function calculateTotal() {
      return this.quotaServices.reduce(this.getQuota.bind(this), 0);
    }

    function validate() {
      this.postPoolsDefault.post([
        this.quotaServices.reduce(this.packQuotas.bind(this), {}), true]);
    }

    function packQuotas(acc, name) {
      var service = this.getFlag(name);
      var keyName = (name == "kv" ? "m" : (name + "M")) + "emoryQuota";
      if (!this.isWithFlag || (service && service.value)) {
        acc[keyName] = this.getField(name).value;
      }
      return acc;
    }

    function getQuota(acc, name) {
      var flag = this.getFlag(name);
      var field = this.getField(name);
      return acc + (((!flag || flag.value) && field.value) || 0);
    }

    function createToggleFieldStream(serviceGroupName) {
      var group = this.getFlag(serviceGroupName);
      if (group) {
        group.valueChanges
          .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
          .subscribe(this.toggleFields(serviceGroupName).bind(this));
      }
    }

    function toggleFields(name) {
      return function () {
        this.getField(name)[this.getFlag(name).value ? "enable" : "disable"]({onlySelf: true});
      }
    }

    function getFlag(name) {
      return this.group.get("flag." + name);
    }

    function getField(name) {
      return this.group.get("field." + name);
    }

  })(window.rxjs);
