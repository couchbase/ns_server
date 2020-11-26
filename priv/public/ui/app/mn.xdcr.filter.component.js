import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {merge} from '/ui/web_modules/rxjs.js';
import {map, pluck} from '/ui/web_modules/rxjs/operators.js';

import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnFormService} from "./mn.form.service.js";

export {MnXDCRFilterComponent};

class MnXDCRFilterComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-filter",
      templateUrl: "/ui/app/mn.xdcr.filter.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "bucket",
        "group",
        "xdcrGroup",
        "isEditMode",
        "settingsPipe"
      ]
    })
  ]}

  static get parameters() { return [
    MnXDCRService,
    MnFormService
  ]}

  constructor(mnXDCRService, mnFormService) {
    super();

    this.form = mnFormService.create(this);

    this.formHelper =
      mnFormService.create(this)
      .setFormGroup({enableFilters: false});

    this.postRegexpValidation =
      mnXDCRService.stream.postRegexpValidation;
    this.postSettingsReplicationsValidation =
      mnXDCRService.stream.postSettingsReplicationsValidation;
    this.postCreateReplication =
      mnXDCRService.stream.postCreateReplication;
    this.postSettingsReplications =
      mnXDCRService.stream.postSettingsReplications;

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

  }

  ngOnInit() {
    this.form
      .setFormGroup(this.group)
      .setPackPipe(map(this.pack.bind(this)))
      .setSourceShared(this.settingsPipe)
      .setPostRequest(this.postRegexpValidation)
      .setValidation(this.postRegexpValidation)
      .trackSubmit()
      .clearErrors();

    this.formHelper.group.patchValue({
      enableFilters: !!this.group.get("filterExpression").value
    });
  }

  pack() {
    return {
      expression: this.group.get("filterExpression").value,
      docId: this.group.get("docId").value,
      bucket: this.bucket || ""
    };
  }
}
