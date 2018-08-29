var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnClientCertificate =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnClientCertificate, mn.helper.MnEventableComponent);

    MnClientCertificate.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-client-certificate.html",
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnClientCertificate.parameters = [
      mn.services.MnSecurity,
      mn.services.MnPermissions,
      mn.services.MnAlerts,
      mn.services.MnAdmin
    ];

    MnClientCertificate.prototype.maybeDisableField = maybeDisableField;
    MnClientCertificate.prototype.setInitialValue = setInitialValue;
    MnClientCertificate.prototype.getValue = getValue;
    MnClientCertificate.prototype.addItem = addItem;
    MnClientCertificate.prototype.removeField = removeField;

    return MnClientCertificate;

    function MnClientCertificate(mnSecurityService, mnPermissionsService, mnAlertsService, mnAdminService) {
      mn.helper.MnEventableComponent.call(this);

      this.onSubmit = new Rx.Subject();
      this.clientCertificateForm = new ng.forms.FormGroup({
        state: new ng.forms.FormControl(),
        prefixes: new ng.forms.FormArray([])
      });

      this.securityWrite = mnPermissionsService.createPermissionStream("admin.security!write");
      this.atLeast50 = mnAdminService.stream.compatVersion.pipe(Rx.operators.pluck("atLeast50"));
      this.atLeast51 = mnAdminService.stream.compatVersion.pipe(Rx.operators.pluck("atLeast51"));
      this.postClientCertAuth = mnSecurityService.stream.postClientCertAuth;

      this.isErrorString = this.postClientCertAuth.error.pipe(
        Rx.operators.map(function (rv) {
          return _.isString(rv);
        })
      );

      this.isStateDisabled = this.clientCertificateForm.valueChanges.pipe(
        Rx.operators.pluck("state"),
        Rx.operators.distinctUntilChanged(),
        Rx.operators.map(function (value) {
          return value == "disable";
        })
      );

      this.isLastPrefix =
        this.clientCertificateForm.valueChanges.pipe(
          Rx.operators.pluck("prefixes", "length"),
          Rx.operators.map(function (length) {
            return length === 1;
          })
        );
      mnSecurityService.stream.getClientCertAuth
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.setInitialValue.bind(this));

      this.securityWrite
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeDisableField.bind(this));

      this.maybeDisableControls =
        Rx.combineLatest(
          this.isStateDisabled,
          this.securityWrite
        ).pipe(
          Rx.operators.map(function (values) {
            return !values[1] || values[0];
          }),
          Rx.operators.takeUntil(this.mnOnDestroy)
        );

      this.maybeDisableControls
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(maybeDisablePrefixesField.bind(this));

      this.postClientCertAuth.success
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(mnAlertsService.success("Settings saved successfully!"))

      this.onSubmit.pipe(
        Rx.operators.tap(this.postClientCertAuth.clearError.bind(this.postClientCertAuth)),
        Rx.operators.withLatestFrom(this.atLeast50, this.atLeast51),
        Rx.operators.map(this.getValue.bind(this)),
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(this.postClientCertAuth.post.bind(this.postClientCertAuth));
    }

    function removeField() {
      var last = this.clientCertificateForm.get('prefixes').length - 1;
      this.clientCertificateForm.get('prefixes').removeAt(last);
    }

    function getValue(value) {
      var state =  this.clientCertificateForm.get("state");
      var prefixes = this.clientCertificateForm.get("prefixes");
      if (!value[1] && value[0]) {
        return [{
          state: state.value,
          path: prefixes.value[0].path,
          prefix: prefixes.value[0].prefix,
          delimiter: prefixes.value[0].delimiter,
        }, value[1]];
      } else {
        return [{
          state: state.value,
          prefixes: prefixes.value
        }, value[1]];
      }
    }

    function maybeDisablePrefixesField(value) {
      this.clientCertificateForm.get("prefixes")[value ? "disable" : "enable"]({onlySelf: true});
    }
    function maybeDisableField(value) {
      this.clientCertificateForm.get("state")[value ? "enable" : "disable"]({onlySelf: true});
    }
    function addItem(value) {
      this.clientCertificateForm.get("prefixes").push(new ng.forms.FormGroup({
        path: new ng.forms.FormControl(value.path),
        prefix: new ng.forms.FormControl(value.prefix),
        delimiter: new ng.forms.FormControl(value.delimiter)
      }))
    }

    function setInitialValue(value) {
      if (value.prefixes.length) {
        value.prefixes.forEach(this.addItem.bind(this));
      } else {
        this.addItem({delimiter: '', prefix: '', path: 'subject.cn'});
      }
      this.clientCertificateForm.get("state").patchValue(value.state);
    }

  })(window.rxjs);
