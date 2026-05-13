/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {merge, pipe} from 'rxjs';
import {map, mapTo, filter, startWith, delay,
        withLatestFrom, takeUntil} from 'rxjs/operators';

import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnFormService} from "./mn.form.service.js";
import {MnKeyspaceSelectorService} from "./mn.keyspace.selector.service.js";
import {MnAdminService} from "./mn.admin.service.js";
import template from "./mn.xdcr.filter.html";

export {MnXDCRFilterComponent};

class MnXDCRFilterComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-filter",
      template,
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "bucket",
        "group",
        "xdcrGroup",
        "isEditMode",
        "settingsPipe",
        "formHelper"
      ]
    })
  ]}

  static get parameters() { return [
    MnXDCRService,
    MnFormService,
    MnKeyspaceSelectorService,
    MnAdminService
  ]}

  constructor(mnXDCRService, mnFormService, mnKeyspaceSelectorService, mnAdminService) {
    super();

    this.form = mnFormService.create(this);

    this.postRegexpValidation =
      mnXDCRService.stream.postRegexpValidation;
    this.postSettingsReplicationsValidation =
      mnXDCRService.stream.postSettingsReplicationsValidation;
    this.postCreateReplication =
      mnXDCRService.stream.postCreateReplication;
    this.postCreateReplicationValidation =
      mnXDCRService.stream.postCreateReplicationValidation;
    this.postSettingsReplications =
      mnXDCRService.stream.postSettingsReplications;
    this.compatVersion70 =
      mnAdminService.stream.compatVersion70;
    this.compatVersion80 = mnAdminService.stream.compatVersion80;
    this.majorMinorVersion = mnAdminService.stream.majorMinorVersion;

    this.mnKeyspaceSelectorService = mnKeyspaceSelectorService;

    this.errors = merge(
      this.postRegexpValidation.success,
      this.postRegexpValidation.error,
      this.postCreateReplication.error,
      this.postSettingsReplications.error,
      this.postSettingsReplicationsValidation.error
    ).pipe(map(errors => {
      return errors &&
        (errors.error ? errors.error._ ? errors.error._ :
         errors.error : errors.filterExpression);
    }));

    function extractTombstoneError(error) {
      if (!error) {
        return null;
      }
      let messages = [
        error.filterDeletionsWithExpression,
        error.filterExpirationsWithExpression
      ].filter(Boolean);
      return messages.length ? messages.join(" ") : null;
    }

    this.tombstoneKeyFilterError = merge(
      this.postCreateReplication.error.pipe(map(extractTombstoneError)),
      this.postSettingsReplications.error.pipe(map(extractTombstoneError)),
      this.postSettingsReplicationsValidation.error.pipe(map(extractTombstoneError)),
      this.postCreateReplicationValidation.error.pipe(map(extractTombstoneError)),
      this.postCreateReplication.success.pipe(mapTo(null)),
      this.postSettingsReplications.success.pipe(mapTo(null)),
      this.postSettingsReplicationsValidation.success.pipe(mapTo(null)),
      this.postCreateReplicationValidation.success.pipe(mapTo(null))
    );

  }

  ngOnInit() {
    this.mnKeyspaceSelector =
      this.mnKeyspaceSelectorService.createCollectionSelector({
        component: this,
        steps: ["bucket", "scope", "collection"]
      });

    let validateOnStream =
        merge(this.group.valueChanges,
              this.mnKeyspaceSelector.stream.step.pipe(filter(v => v == "ok")));

    this.form
      .setFormGroup(this.group)
      .setPackPipe(pipe(withLatestFrom(this.mnKeyspaceSelector.stream.result,
                                       this.compatVersion70),
                        filter(([, r, is70]) => is70 ?
                               r.bucket && r.scope && r.collection :
                               !!this.bucket),
                        map(this.pack.bind(this))))
      .setSourceShared(this.settingsPipe)
      .setPostRequest(this.postRegexpValidation)
      .setValidation(this.postRegexpValidation, null, validateOnStream)
      .trackSubmit()
      .clearErrors();

    this.settingsPipe
    .pipe(delay(0),
          takeUntil(this.mnOnDestroy))
    .subscribe((settings) => {
      this.formHelper.group.patchValue({
        enableFilters: !!settings.filterExpression ||
          settings.filterExpiration ||
          settings.filterDeletion ||
          settings.filterDeletionsWithExpression ||
          settings.filterExpirationsWithExpression ||
          settings.filterBypassExpiry ||
          settings.filterBinary
      });

      if (settings.filterDeletionsWithExpression &&
          settings.filterExpirationsWithExpression) {
        this.formHelper.group.get("tombstoneKeyFilter").setValue(true,
          {emitEvent: false});
        this.scenarioAActive = true;
      } else if (settings.filterDeletionsWithExpression ||
                 settings.filterExpirationsWithExpression) {
        this.formHelper.group.get("tombstoneKeyFilter").setValue(false,
          {emitEvent: false});
        this.scenarioAActive = false;
      }
    });

    let hasSourceBucketField = this.xdcrGroup.get("fromBucket");
    if (hasSourceBucketField) {
      hasSourceBucketField.valueChanges
        .pipe(startWith(hasSourceBucketField.value),
              takeUntil(this.mnOnDestroy))
        .subscribe(v => {
          let action = v ? "enable" : "disable";
          this.formHelper.group.get("enableFilters")[action]({onlySelf: true});
        });
    }

    let tombstoneKeyFilter = this.formHelper.group.get("tombstoneKeyFilter");
    let filterExpiration = this.xdcrGroup.get("filterExpiration");
    let filterDeletion = this.xdcrGroup.get("filterDeletion");
    let filterExpirationsWithExpression =
        this.xdcrGroup.get("filterExpirationsWithExpression");
    let filterDeletionsWithExpression =
        this.xdcrGroup.get("filterDeletionsWithExpression");
    let updateMasterFromSubCheckboxes = () => {
      tombstoneKeyFilter.setValue(
        filterDeletionsWithExpression.value && filterExpirationsWithExpression.value,
        {emitEvent: false});
    };

    tombstoneKeyFilter.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((v) => {
        this.scenarioAActive = v;
        this.xdcrGroup.patchValue({
          filterExpiration: v,
          filterDeletion: v,
          filterExpirationsWithExpression: v,
          filterDeletionsWithExpression: v
        });
      });

    filterDeletionsWithExpression.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(updateMasterFromSubCheckboxes);

    filterExpirationsWithExpression.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(updateMasterFromSubCheckboxes);

    filterExpiration.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((v) => {
        if (!v) {
          filterExpirationsWithExpression.setValue(false);
        }
      });

    filterDeletion.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((v) => {
        if (!v) {
          filterDeletionsWithExpression.setValue(false);
        }
      });
  }

  pack([, result, is70]) {
    let rv = {
      expression: this.group.get("filterExpression").value,
      docId: this.group.get("docId").value,
    };
    if (is70) {
      rv.bucket = result.bucket.name;
      rv.scope = result.scope.name;
      rv.collection = result.collection.name;
    } else {
      rv.bucket = this.bucket;
    }
    return rv;
  }
}
