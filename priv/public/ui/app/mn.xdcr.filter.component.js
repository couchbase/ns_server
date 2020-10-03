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
        "group",
        "bucket",
        "isEditMode"
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

    this.errors = merge(
      this.postRegexpValidation.success,
      this.postRegexpValidation.error,
      this.postSettingsReplicationsValidation.error
    ).pipe(map(errors => errors && (errors.error || errors.filterExpression)));


    this.form
      .setFormGroup({docId: ""})
      .setPackPipe(map(this.pack.bind(this)))
      .setPostRequest(this.postRegexpValidation)
      .trackSubmit()
      .clearErrors();
  }

  pack() {
    return {
      expression: this.group.get("filterExpression").value,
      docId: this.form.group.get("docId").value,
      bucket: this.bucket || ""
    };
  }
}
