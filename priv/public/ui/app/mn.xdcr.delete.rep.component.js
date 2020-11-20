import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {NgbActiveModal} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {map} from '/ui/web_modules/rxjs/operators.js';

import {$rootScope} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnFormService} from "./mn.form.service.js";

export {MnXDCRDeleteRepComponent};

class MnXDCRDeleteRepComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.xdcr.delete.rep.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item"
      ]
    })
  ]}

  static get parameters() { return [
    NgbActiveModal,
    MnXDCRService,
    MnFormService,
    $rootScope
  ]}

  constructor(activeModal, mnXDCRService, mnFormService, $rootScope) {
    super();

    this.form = mnFormService.create(this)
      .setPackPipe(map(() => this.item.id))
      .setPostRequest(mnXDCRService.stream.deleteCancelXDCR)
      .successMessage("Replication deleted successfully!")
      .showGlobalSpinner()
      .success(function () {
        activeModal.close();
        $rootScope.$broadcast("reloadTasksPoller");
      });

    this.activeModal = activeModal;
  }
}
