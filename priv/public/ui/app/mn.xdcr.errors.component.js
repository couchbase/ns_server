import {Component, ChangeDetectionStrategy} from "/ui/web_modules/@angular/core.js";
import {NgbActiveModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js";

import {MnFormService} from "./mn.form.service.js";

export {MnXDCRErrorsComponent};

class MnXDCRErrorsComponent {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.xdcr.errors.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "errors"
      ]
    })
  ]}

  static get parameters() { return [
    NgbActiveModal,
    MnFormService
  ]}

  constructor(activeModal, mnFormService) {
    this.activeModal = activeModal;
    this.form = mnFormService.create(this)
      .setFormGroup({})
      .hasNoPostRequest()
  }
}
