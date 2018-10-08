var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnEmailAlerts =
  (function (Rx) {
    "use strict";

    mn.core.extend(MnEmailAlerts, mn.core.MnEventableComponent);

    MnEmailAlerts.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-email-alerts.html",
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnEmailAlerts.parameters = [
      mn.services.MnSettings,
      mn.services.MnPermissions,
      mn.services.MnAlerts,
      mn.services.MnAdmin
    ];

    MnEmailAlerts.prototype.setInitFormValue = setInitFormValue;
    MnEmailAlerts.prototype.maybeDisableFields = maybeDisableFields;
    MnEmailAlerts.prototype.disableEnableFiled = disableEnableFiled
    MnEmailAlerts.prototype.unpack = unpack;
    MnEmailAlerts.prototype.getAlertDescription = getAlertDescription;
    MnEmailAlerts.prototype.generateAlertsGroup = generateAlertsGroup;
    MnEmailAlerts.prototype.prepareDataForSending = prepareDataForSending;
    MnEmailAlerts.prototype.doAlertsPost = doAlertsPost;

    var alerts = ["auto_failover_node",
                  "auto_failover_maximum_reached",
                  "auto_failover_other_nodes_down",
                  "auto_failover_cluster_too_small",
                  "auto_failover_disabled",
                  "ip",
                  "disk",
                  "overhead",
                  "ep_oom_errors",
                  "ep_item_commit_failed",
                  "audit_dropped_events",
                  "indexer_ram_max_usage",
                  "ep_clock_cas_drift_threshold_exceeded",
                  "communication_issue"
                 ];

    return MnEmailAlerts;

    function MnEmailAlerts(mnSettingsService, mnPermissionsService, mnAlertsService, mnAdminService) {
      mn.core.MnEventableComponent.call(this);

      this.onSubmit = new Rx.Subject();
      this.onTestEmail = new Rx.Subject();
      this.formGroup = new ng.forms.FormGroup({
        enabled: new ng.forms.FormControl(),
        emailServer: new ng.forms.FormGroup({
          user: new ng.forms.FormControl(),
          pass: new ng.forms.FormControl(),
          host: new ng.forms.FormControl(),
          port: new ng.forms.FormControl(),
          encrypt: new ng.forms.FormControl()
        }),
        recipients: new ng.forms.FormControl(),
        sender: new ng.forms.FormControl(),
        alerts: new ng.forms.FormGroup({})
      });

      this.alerts = alerts;

      this.alerts.forEach(this.generateAlertsGroup.bind(this));

      this.enabledValueChanges = this.formGroup.get("enabled").valueChanges;

      var initValue =
          mnSettingsService.stream.getAlerts
          .pipe(Rx.operators.first());

      initValue.pipe(Rx.operators.map(this.unpack.bind(this)))
        .subscribe(this.setInitFormValue.bind(this));

      this.postAlerts = mnSettingsService.stream.postAlerts;
      this.postAlertsValidation = mnSettingsService.stream.postAlertsValidation;
      this.httpError = Rx.merge(this.postAlerts.error, this.postAlertsValidation.error);

      this.postTestEmail = mnSettingsService.stream.postTestEmail;
      this.settingsWrite = mnPermissionsService.createPermissionStream("admin.settings!write");

      Rx.combineLatest(this.enabledValueChanges, this.settingsWrite)
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeDisableFields.bind(this));

      this.settingsWrite
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.disableEnableFiled.bind(this));

      this.postAlerts.success
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(mnAlertsService.success("Settings saved successfully!"));

      this.settingsWrite
        .pipe(Rx.operators.switchMap(function (v) {
          return v ? this.formGroup.valueChanges : Rx.NEVER;
        }.bind(this)),
              Rx.operators.debounceTime(0),
              Rx.operators.map(this.prepareDataForSending.bind(this)),
              Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.doAlertsPost(true).bind(this));

      this.onSubmit.pipe(
        Rx.operators.tap(this.postAlerts.clearError.bind(this.postAlerts)),
        Rx.operators.map(this.prepareDataForSending.bind(this)),
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(this.doAlertsPost(false).bind(this));
    }

    function doAlertsPost(validate) {
      return function (data) {
        this[validate ? "postAlertsValidation" : "postAlerts"].post([data, validate]);
      };
    }

    function prepareDataForSending(data) {
      var result = {
        alerts: []
      };
      result.enabled = this.formGroup.get("enabled").value;
      result.sender = this.formGroup.get("sender").value;
      result.recipients = this.formGroup.get("recipients").value.replace(/\s+/g, ',');
      result.emailUser = this.formGroup.get("emailServer.user").value;
      result.emailPass = this.formGroup.get("emailServer.pass").value;
      result.emailHost = this.formGroup.get("emailServer.host").value;
      result.emailPort = this.formGroup.get("emailServer.port").value;
      result.emailEncrypt = this.formGroup.get("emailServer.encrypt").value;

      var alerts = this.formGroup.get("alerts").value;
      Object.keys(alerts).forEach(function(key) {
        !!alerts[key] && result.alerts.push(key);
      });

      result.alerts = result.alerts.join(',');
      return result;
    }

    function unpack(v) {
      v.recipients = v.recipients.join('\n');
      v.alerts = v.alerts.reduce(function (acc, item) {
        acc[item] = true;
        return acc;
      }, {})
      return v;
    }

    function getAlertDescription(name) {
      switch (name) {
      case this.alerts[0]: return 'Node was auto-failed-over';
      case this.alerts[1]: return 'Maximum number of auto-failed-over nodes was reached';
      case this.alerts[2]: return 'Node wasn\'t auto-failed-over as other nodes are down at the same time';
      case this.alerts[3]: return 'Node was not auto-failed-over as there are not enough nodes in the cluster running the same service';
      case this.alerts[4]: return 'Node was not auto-failed-over as auto-failover for one or more services running on the node is disabled';
      case this.alerts[5]: return 'Node\'s IP address has changed unexpectedly';
      case this.alerts[6]: return 'Disk space used for persistent storage has reached at least 90% of capacity';
      case this.alerts[7]: return 'Metadata overhead is more than 50%';
      case this.alerts[8]: return 'Bucket memory on a node is entirely used for metadata';
      case this.alerts[9]: return 'Writing data to disk for a specific bucket has failed';
      case this.alerts[10]: return 'Writing event to audit log has failed';
      case this.alerts[11]: return 'Approaching full Indexer RAM warning';
      case this.alerts[12]: return 'Remote mutation timestamp exceeded drift threshold';
      case this.alerts[13]: return 'Communication issues among some nodes in the cluster';
      }
    }

    function setInitFormValue(v) {
      this.formGroup.patchValue(v);
    }

    function generateAlertsGroup(alertName) {
      this.formGroup.get("alerts").addControl(alertName, new ng.forms.FormControl());
    }

    function disableEnableFiled(value) {
      var method = value ? "enable" : "disable";
      this.formGroup.get("enabled")[method]({onlySelf: true, emitEvent: false});
    }
    function maybeDisableFields(values) {
      var settings = {onlySelf: true, emitEvent: false};
      var method = (values[1] && values[0]) ? "enable" : "disable";
      this.formGroup.get("emailServer")[method](settings);
      this.formGroup.get("recipients")[method](settings);
      this.formGroup.get("sender")[method](settings);
      this.formGroup.get("alerts")[method](settings);
    }

  })(window.rxjs);
