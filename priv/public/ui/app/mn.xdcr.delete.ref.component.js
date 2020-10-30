import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {NgbActiveModal} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {map} from '/ui/web_modules/rxjs/operators.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnFormService} from "./mn.form.service.js";

export {MnXDCRDeleteRefComponent};

class MnXDCRDeleteRefComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.xdcr.delete.ref.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item"
      ]
    })
  ]}

  static get parameters() { return [
    NgbActiveModal,
    MnXDCRService,
    MnFormService
  ]}

  constructor(activeModal, mnXDCRService, mnFormService) {
    super();

    this.form = mnFormService.create(this)
      .setPackPipe(map(() => this.item.name))
      .setPostRequest(mnXDCRService.stream.deleteRemoteClusters)
      .successMessage("Replication deleted successfully!")
      .success(() => {
        activeModal.close();
        mnXDCRService.stream.updateRemoteClusters.next();
      });

    this.activeModal = activeModal;
    this.deleteRemoteClusters = mnXDCRService.stream.deleteRemoteClusters;
  }
}
