var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnServicesConfig =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnServicesConfig, mn.helper.MnEventableComponent);

    MnServicesConfig.annotations = [
      new ng.core.Component({
        selector: "mn-services-config",
        templateUrl: "app-new/mn-services-config.html",
        inputs: [
          "group",
          "servicesOnly"
        ],
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnServicesConfig.parameters = [
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
    MnServicesConfig.prototype.triggerUpdate = triggerUpdate;

    return MnServicesConfig;

    function MnServicesConfig(mnAdminService, mnPoolsService) {
      mn.helper.MnEventableComponent.call(this);
      this.poolsDefaultHttp = mnAdminService.stream.poolsDefaultHttp;
      this.isEnterprise = mnPoolsService.stream.isEnterprise;
      this.quotaServices = ["kv", "index", "fts", "cbas", "eventing"];
    }

    function ngOnInit() {
      if (this.servicesOnly) {
        return;
      }
      this.focusFieldSubject = new Rx.BehaviorSubject(
        this.quotaServices.find(this.selectInitialFocus.bind(this))
      );
      this.total = this.group.valueChanges.pipe(
        Rx.operators.map(this.calculateTotal.bind(this))
      );
      this.quotaServices.forEach(this.createToggleFieldStream.bind(this))

      this.group.valueChanges.pipe(
        Rx.operators.debounce(function () {
          return Rx.interval(300);
        }),
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(this.validate.bind(this));

      //trigger servicesGroup.valueChanges in order to calculate total
      setTimeout(this.triggerUpdate.bind(this), 0);
    }

    function selectInitialFocus(service) {
      return this.group.value.field[service];
    }

    function calculateTotal() {
      return this.quotaServices.reduce(this.getQuota.bind(this), 0);
    }

    function validate() {
      this.poolsDefaultHttp.post([
        this.quotaServices.reduce(this.packQuotas.bind(this), {}), true]);
    }

    function packQuotas(acc, name) {
      var service = this.group.get("flag." + name);
      var keyName = (name == "kv" ? "m" : (name + "M")) + "emoryQuota";
      if (service && service.value) {
        acc[keyName] = this.group.get("field." + name).value;
      }
      return acc;
    }

    function getQuota(acc, name) {
      var flag = this.group.get("flag." + name);
      var field = this.group.get("field." + name);
      return acc + ((flag && flag.value && field.value) || 0);
    }

    function createToggleFieldStream(serviceGroupName) {
      var group = this.group.get("flag." + serviceGroupName);
      if (group) {
        group.valueChanges
          .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
          .subscribe(this.toggleFields(serviceGroupName).bind(this));
      }
    }

    function toggleFields(serviceGroupName) {
      return function () {
        this.group.get("field." + serviceGroupName)
        [this.group.get("flag." + serviceGroupName).value ? "enable" : "disable"]({onlySelf: true});
      }
    }

    function triggerUpdate() {
      this.group.patchValue(this.group.value);
    }

  })(window.rxjs);
