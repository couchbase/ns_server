var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnAutoCompaction =
  (function (Rx) {
    "use strict";

    mn.core.extend(MnAutoCompaction, mn.core.MnEventableComponent);

    MnAutoCompaction.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-auto-compaction.html",
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnAutoCompaction.parameters = [
      mn.services.MnSettings,
      mn.services.MnPermissions,
      mn.services.MnAlerts,
      mn.services.MnHelper
    ];

    MnAutoCompaction.prototype.setInitFormValue = setInitFormValue;
    MnAutoCompaction.prototype.getValue = getValue;
    MnAutoCompaction.prototype.doPostAutoCompaction = doPostAutoCompaction;

    return MnAutoCompaction;

    function MnAutoCompaction(mnSettingsService, mnPermissionsService, mnAlertsService, mnHelperService) {
      mn.core.MnEventableComponent.call(this);

      this.onSubmit = new Rx.Subject();

      this.formGroup = new ng.forms.FormGroup({
        allowedTimePeriod: new ng.forms.FormGroup({
          abortOutside: new ng.forms.FormControl(false),
          fromHour: new ng.forms.FormControl(),
          fromMinute: new ng.forms.FormControl(),
          toHour: new ng.forms.FormControl(),
          toMinute: new ng.forms.FormControl()
        }),
        databaseFragmentationThreshold: new ng.forms.FormGroup({
          percentage: new ng.forms.FormControl(),
          size: new ng.forms.FormControl()
        }),
        viewFragmentationThreshold: new ng.forms.FormGroup({
          percentage: new ng.forms.FormControl(),
          size: new ng.forms.FormControl()
        }),
        indexFragmentationThreshold: new ng.forms.FormGroup({
          percentage: new ng.forms.FormControl()
        }),
        indexCircularCompaction: new ng.forms.FormGroup({
          daysOfWeek: new ng.forms.FormGroup(
            mnHelperService.daysOfWeek.reduce(function (acc, day) {
              acc[day] = new ng.forms.FormControl(false);
              return acc;
            }, {})
          ),
          interval: new ng.forms.FormGroup({
            abortOutside: new ng.forms.FormControl(),
            fromHour: new ng.forms.FormControl(),
            fromMinute: new ng.forms.FormControl(),
            toHour: new ng.forms.FormControl(),
            toMinute: new ng.forms.FormControl()
          })
        }),
        indexCompactionMode: new ng.forms.FormControl(),
        parallelDBAndViewCompaction: new ng.forms.FormControl(),
        purgeInterval: new ng.forms.FormControl()
      });

      this.settingsWrite = mnPermissionsService.createPermissionStream("settings!write");

      var initData = mnSettingsService.stream.getAutoCompactionFirst;

      initData.subscribe(this.setInitFormValue.bind(this));

      this.postAutoCompaction = mnSettingsService.stream.postAutoCompaction;
      this.postAutoCompactionValidation = mnSettingsService.stream.postAutoCompactionValidation;

      this.formGroup.valueChanges.pipe(
        Rx.operators.debounceTime(0),
        Rx.operators.map(this.getValue.bind(this)),
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(this.doPostAutoCompaction(true).bind(this));

      this.formError = Rx
        .merge(
          this.postAutoCompaction.error,
          this.postAutoCompactionValidation.error
        ).pipe(Rx.operators.startWith({}),
               Rx.operators.map(function (e) {
                 return e && e.errors ? e.errors : {};
               }));

      this.postAutoCompaction.success
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(mnAlertsService.success("Settings saved successfully!"));

      this.onSubmit.pipe(
        Rx.operators.tap(this.postAutoCompaction.clearError.bind(this.postAutoCompaction)),
        Rx.operators.map(this.getValue.bind(this)),
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(this.doPostAutoCompaction(false).bind(this));
    }

    function doPostAutoCompaction(validate) {
      return function (data) {
        this[validate ? "postAutoCompactionValidation" : "postAutoCompaction"].post([data, validate]);
      };
    }

    function setInitFormValue(v) {
      this.formGroup.patchValue(v, {emitEvent: false});
    }

    function getValue(v) {
      v = _.clone(v || this.formGroup.value, true);
      var icc = v.indexCircularCompaction;
      if (icc) {
        icc.daysOfWeek = Object
          .keys(icc.daysOfWeek)
          .reduce(function (acc, day) {
            if (icc.daysOfWeek[day]) {
              acc.push(day);
            }
            return acc;
          }, [])
          .join(",");
      }
      return v;
    }

  })(window.rxjs);
