var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnAudit =
  (function (Rx) {
    "use strict";

    mn.core.extend(MnAudit, mn.core.MnEventableComponent);

    MnAudit.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-audit.html",
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnAudit.parameters = [
      mn.services.MnHelper,
      mn.services.MnSecurity,
      mn.services.MnPermissions,
      mn.services.MnAlerts,
      mn.services.MnAdmin,
      mn.services.MnPools
    ];

    MnAudit.prototype.unpackGetAudit = unpackGetAudit;
    MnAudit.prototype.setInitialValue = setInitialValue;
    MnAudit.prototype.maybeDisableFields = maybeDisableFields;
    MnAudit.prototype.disableEnableFiled = disableEnableFiled;
    MnAudit.prototype.getDescriptorsByModule = getDescriptorsByModule;
    MnAudit.prototype.maybeAddDescriptorsFields = maybeAddDescriptorsFields;
    MnAudit.prototype.getDisabledByID = getDisabledByID;
    MnAudit.prototype.getEnding = getEnding;
    MnAudit.prototype.prepareDataForSending = prepareDataForSending;
    MnAudit.prototype.doAuditPost = doAuditPost;
    MnAudit.prototype.getFormValue = getFormValue;

    return MnAudit;

    function MnAudit(mnHelperService, mnSecurityService, mnPermissionsService, mnAlertsService, mnAdminService, mnPoolsService) {
      mn.core.MnEventableComponent.call(this);

      this.IEC = mnHelperService.IEC;

      this.onSubmit = new Rx.Subject();

      this.auditForm = new ng.forms.FormGroup({
        auditdEnabled: new ng.forms.FormControl(),
        logPath: new ng.forms.FormControl(),
        rotateInterval: new ng.forms.FormControl(),
        rotateSize: new ng.forms.FormControl(),
        rotateUnit: new ng.forms.FormControl()
      });

      this.securityWrite = mnPermissionsService.createPermissionStream("admin.security!write");
      this.atLeast55 = mnAdminService.stream.compatVersion.pipe(Rx.operators.pluck("atLeast55"));
      this.isEnterprise = mnPoolsService.stream.isEnterprise;
      this.getAuditDescriptors = mnSecurityService.stream.getAuditDescriptors;
      this.getAudit = mnSecurityService.stream.getAudit;
      this.postAudit = mnSecurityService.stream.postAudit;
      this.postAuditValidation = mnSecurityService.stream.postAuditValidation;

      this.httpError = Rx.merge(this.postAudit.error, this.postAuditValidation.error);

      Rx.combineLatest(this.atLeast55, this.isEnterprise)
        .pipe(Rx.operators.first(),
              Rx.operators.filter(function (value) {
                return value.every(Boolean);
              }))
        .subscribe(this.maybeAddDescriptorsFields.bind(this));

      this.maybeItIsPlural =
        this.auditForm.get("rotateInterval").valueChanges
        .pipe(Rx.operators.map(this.getEnding.bind(this)),
              Rx.operators.multicast(function () {return new Rx.ReplaySubject(1);}),Rx.operators.refCount());

      Rx.combineLatest(this.auditForm.get("auditdEnabled").valueChanges, this.securityWrite)
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeDisableFields.bind(this));

      this.securityWrite
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.disableEnableFiled.bind(this));

      var disabledByID =
          this.getAudit
          .pipe(Rx.operators.pluck("disabled"),
                Rx.operators.map(this.getDisabledByID.bind(this)));

      this.descriptorsByModule =
        Rx.combineLatest(this.getAuditDescriptors, disabledByID)
        .pipe(Rx.operators.map(this.getDescriptorsByModule.bind(this)),
              Rx.operators.publishReplay(1),
              Rx.operators.refCount());

      this.getAudit
        .pipe(Rx.operators.map(this.unpackGetAudit.bind(this)),
              Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.setInitialValue.bind(this));

      this.securityWrite
        .pipe(Rx.operators.switchMap(function (v) {
          return v ? this.auditForm.valueChanges : Rx.NEVER;
        }.bind(this)),
              Rx.operators.debounceTime(0),
              Rx.operators.map(this.prepareDataForSending.bind(this)),
              Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.doAuditPost(true).bind(this));

      this.onSubmit
        .pipe(Rx.operators.tap(this.postAudit.clearError.bind(this.postAudit)),
              Rx.operators.map(this.getFormValue.bind(this)),
              Rx.operators.map(this.prepareDataForSending.bind(this)),
              Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.doAuditPost(false).bind(this));

      this.postAudit.success
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(mnAlertsService.success("Settings saved successfully!"));
    }

    function formatTimeUnit(unit) {
      switch (unit) {
      case 'minutes': return 60;
      case 'hours': return 3600;
      case 'days': return 86400;
      }
    }

    function getFormValue() {
      return this.auditForm.value;
    }

    function prepareDataForSending(data) {
      var result = {
        auditdEnabled: data.auditdEnabled
      };
      if (data.descriptors) {
        result.disabled = [];
        Object.keys(data.descriptors).forEach(function(key) {
          Object.keys(data.descriptors[key]).forEach(function (id) {
            !data.descriptors[key][id] && result.disabled.push(id);
          });
        });
        result.disabled = result.disabled.join(',');
      }
      if (data.disabledUsers) {
        result.disabledUsers = data.disabledUsers.replace(/\/couchbase/gi,"/local");
      }
      if (data.auditdEnabled) {
        result.rotateInterval = data.rotateInterval * formatTimeUnit(data.rotateUnit);
        result.logPath = data.logPath;
        result.rotateSize = data.rotateSize;
      }
      if (data.rotateSize) {
        result.rotateSize = data.rotateSize * this.IEC.Mi;
      }
      return result;
    }

    function doAuditPost(validate) {
      return function (data) {
        this[validate ? "postAuditValidation" : "postAudit"].post([data, validate]);
      };
    }

    function getDisabledByID(disabled) {
      return disabled.reduce(function (acc, item) {
        acc[item] = true;
        return acc;
      }, {});
    }

    function getEnding(value) {
      return value !== 1 ? "s" : "";
    }

    function maybeAddDescriptorsFields() {
      this.auditForm.addControl("descriptors", new ng.forms.FormGroup({}));
      this.auditForm.addControl("disabledUsers", new ng.forms.FormControl());
    }

    function getDescriptorsByModule(data) {
      return data[0].reduce(function (acc, item) {
        acc[item.module] = acc[item.module] || [];
        item.value = !data[1][item.id];
        acc[item.module].push(item);
        return acc;
      }, {});
    }

    function disableEnableFiled(value) {
      var method = value ? "enable" : "disable";
      this.auditForm.get("auditdEnabled")[method]({onlySelf: true, emitEvent: false});
    }
    function maybeDisableFields(values) {
      var settings = {onlySelf: true, emitEvent: false};
      var method = (values[1] && values[0]) ? "enable" : "disable";
      this.auditForm.get("logPath")[method](settings);
      this.auditForm.get("rotateInterval")[method](settings);
      this.auditForm.get("rotateSize")[method](settings);
      this.auditForm.get("rotateUnit")[method](settings);
      this.auditForm.get("descriptors")[method](settings);
      this.auditForm.get("disabledUsers")[method](settings);
    }
    function setInitialValue(value) {
      this.auditForm.patchValue(value);
    }

    function unpackGetAudit(data) {
      if (data.rotateInterval % 86400 == 0) {
        data.rotateInterval /= 86400;
        data.rotateUnit = 'days';
      } else if (data.rotateInterval % 3600 == 0) {
        data.rotateInterval /= 3600;
        data.rotateUnit = 'hours';
      } else {
        data.rotateInterval /= 60;
        data.rotateUnit = 'minutes';
      }
      if (data.rotateSize) {
        data.rotateSize = data.rotateSize / this.IEC.Mi;
      }
      if (data.disabledUsers) {
        data.disabledUsers = data.disabledUsers.map(function (user) {
          return user.name + "/" + (user.domain === "local" ? "couchbase" : user.domain);
        }).join(',');
      }
      return data;
    }

  })(window.rxjs);
