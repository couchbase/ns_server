/*
  Copyright 2021-Present Couchbase, Inc.

  Use of this software is governed by the Business Source License included in
  the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
  file, in accordance with the Business Source License, use of this software will
  be governed by the Apache License, Version 2.0, included in the file
  licenses/APL2.txt.
*/

import { Component, ChangeDetectionStrategy } from '/ui/web_modules/@angular/core.js';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnFormService } from './mn.form.service.js';
import { MnSettingsAutoCompactionService  } from './mn.settings.auto.compaction.service.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnPermissions } from '/ui/app/ajs.upgraded.providers.js';
import { UIRouter } from '/ui/web_modules/@uirouter/angular.js';
import { map, takeUntil } from '/ui/web_modules/rxjs/operators.js';
import { pipe, combineLatest, merge } from '/ui/web_modules/rxjs.js';
import { clone } from '../web_modules/ramda.js';
import { FormBuilder } from '/ui/web_modules/@angular/forms.js';

export { MnSettingsAutoCompactionComponent };

class MnSettingsAutoCompactionComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "app/mn.settings.auto.compaction.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnFormService,
    MnPermissions,
    UIRouter,
    MnSettingsAutoCompactionService,
    FormBuilder,
    MnHelperService
  ]}

  constructor(mnFormService, mnPermissions, uiRouter, mnSettingsAutoCompactionService, formBuilder, mnHelperService) {
    super();

    this.postAutoCompaction = mnSettingsAutoCompactionService.stream.postAutoCompaction;
    this.postAutoCompactionValidation = mnSettingsAutoCompactionService.stream.postAutoCompactionValidation;
    this.getAutoCompaction = mnSettingsAutoCompactionService.stream.getAutoCompaction;
    this.permissions = mnPermissions.stream;
    this.uiRouter = uiRouter;
    this.formBuilder = formBuilder;
    this.cancel = this.cancel.bind(this);

    this.httpError = merge(this.postAutoCompaction.error,
                           this.postAutoCompactionValidation.error);

    this.hasErrors = this.httpError
      .pipe(map(val => val && Object.keys(val.errors).length));

    this.transformMBToBytes = mnHelperService.transformMBToBytes;
    this.stringifyValues = mnHelperService.stringifyValues;
    this.flattenData = mnSettingsAutoCompactionService.flattenData;

    let settingsSource = mnSettingsAutoCompactionService.stream.settingsSource;

    this.form = mnFormService.create(this)
      .setFormGroup({
        indexCompactionMode: null,
        allowedTimePeriod: this.formBuilder.group({
          fromHour: null,
          toHour: null,
          fromMinute: null,
          toMinute: null,
          abortOutside: false
        }),
        databaseFragmentationThreshold: this.formBuilder.group({
          percentageFlag: null,
          sizeFlag: null,
          percentage: null,
          size: null
        }),
        viewFragmentationThreshold: this.formBuilder.group({
          percentageFlag: null,
          sizeFlag: null,
          percentage: null,
          size: null
        }),
        indexFragmentationThreshold: this.formBuilder.group({
          percentage: null
        }),
        indexCircularCompaction: this.formBuilder.group({
          daysOfWeek: this.formBuilder.group({
            Monday: null,
            Tuesday: null,
            Wednesday: null,
            Thursday: null,
            Friday: null,
            Saturday: null,
            Sunday: null
          }),
          interval: this.formBuilder.group({
            fromHour: null,
            toHour: null,
            fromMinute: null,
            toMinute: null,
            abortOutside: false
          }),
        }),
        parallelDBAndViewCompaction: null,
        purgeInterval: null,
        timePeriodFlag: null
      })
      .setPackPipe(pipe(map(this.getAutoCompactionData.bind(this))))
      .setSource(settingsSource)
      .setPostRequest(this.postAutoCompaction)
      .setValidation(this.postAutoCompactionValidation, this.hasWritePermissions)
      .clearErrors()
      .showGlobalSpinner()
      .successMessage("Settings saved successfully!");

    this.form.group.disable();

    this.thresholdFlags = combineLatest(
      this.form.group.get('databaseFragmentationThreshold.percentageFlag').valueChanges,
      this.form.group.get('databaseFragmentationThreshold.sizeFlag').valueChanges,
      this.form.group.get('viewFragmentationThreshold.percentageFlag').valueChanges,
      this.form.group.get('viewFragmentationThreshold.sizeFlag').valueChanges
    );

    this.hasWritePermissions = this.permissions
        .pipe(map(permissions => permissions.cluster.settings.autocompaction.write));

    this.hasWritePermissions
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.initiallyEnabledControls.bind(this));

    combineLatest(this.hasWritePermissions,
                  this.thresholdFlags)
      .pipe(map(([hasPermission, flags]) => hasPermission && flags.some(v => v)),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableField.bind(this, 'timePeriodFlag'));

    combineLatest(this.hasWritePermissions,
                  this.thresholdFlags,
                  this.form.group.get('timePeriodFlag').valueChanges)
      .pipe(map(([hasPermission, flags, checked]) =>
        hasPermission && flags.some(v => v) && checked),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableField.bind(this, 'allowedTimePeriod'));

    combineLatest(this.hasWritePermissions,
                  this.form.group.get('indexCompactionMode').valueChanges)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.toggleIndexFragmentation.bind(this));

    this.addThresholdToggle('databaseFragmentationThreshold.percentage');
    this.addThresholdToggle('databaseFragmentationThreshold.size');
    this.addThresholdToggle('viewFragmentationThreshold.percentage');
    this.addThresholdToggle('viewFragmentationThreshold.size');
  }

  addThresholdToggle(control) {
    return combineLatest(this.form.group.get(`${control}Flag`).valueChanges,
                         this.hasWritePermissions)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(([flag, hasPermission]) =>
        this.form.group.get(control)[flag && hasPermission ? 'enable' : 'disable']());
  }

  initiallyEnabledControls(hasPermission) {
    this.maybeDisableField('databaseFragmentationThreshold.percentageFlag', hasPermission);
    this.maybeDisableField('databaseFragmentationThreshold.sizeFlag', hasPermission);
    this.maybeDisableField('viewFragmentationThreshold.percentageFlag', hasPermission);
    this.maybeDisableField('viewFragmentationThreshold.sizeFlag', hasPermission);
    this.maybeDisableField('purgeInterval', hasPermission);
    this.maybeDisableField('parallelDBAndViewCompaction', hasPermission);
    this.maybeDisableField('indexCompactionMode', hasPermission);
    this.maybeDisableField('indexCircularCompaction', hasPermission);
  }

  getAutoCompactionData() {
    let values = clone(this.form.group.value);

    if (values.databaseFragmentationThreshold.size) {
      values.databaseFragmentationThreshold.size = this.transformMBToBytes(values.databaseFragmentationThreshold.size);
    }
    if (values.viewFragmentationThreshold.size) {
      values.viewFragmentationThreshold.size = this.transformMBToBytes(values.viewFragmentationThreshold.size);
    }
    if (values.indexCircularCompaction) {
      values.indexCircularCompaction.daysOfWeek = this.stringifyValues(values.indexCircularCompaction.daysOfWeek)
    } else {
      delete values.indexCircularCompaction;
    }

    values.purgeInterval = Number(values.purgeInterval);

    delete values.databaseFragmentationThreshold.sizeFlag;
    delete values.databaseFragmentationThreshold.percentageFlag;
    delete values.viewFragmentationThreshold.sizeFlag;
    delete values.viewFragmentationThreshold.percentageFlag;
    delete values.timePeriodFlag;

    return this.flattenData(values);
  }

  toggleIndexFragmentation([hasPermission, mode]) {
    let enabled = mode == "circular";

    if (hasPermission) {
      this.maybeDisableField('indexFragmentationThreshold', !enabled);
      this.maybeDisableField('indexCircularCompaction', enabled);
    }
  }

  maybeDisableField(control, enabled) {
    this.form.group.get(control)[enabled ? "enable" : "disable"]();
  }

  cancel() {
    return this.uiRouter.stateService.reload();
  }
}
