import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {NgbActiveModal} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';

import {MnFormService} from "./mn.form.service.js";
import {MnCollectionsService} from './mn.collections.service.js';

export {MnCollectionsAddScopeComponent}

class MnCollectionsAddScopeComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "app/mn.collections.add.scope.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    NgbActiveModal,
    MnCollectionsService,
    MnFormService
  ]}

  constructor(activeModal, mnCollectionsService, mnFormService) {
    super();
    this.activeModal = activeModal;
    this.form = mnFormService.create(this);
    this.buckets = mnCollectionsService.stream.collectionBuckets;
    this.addScopeHttp = mnCollectionsService.stream.addScopeHttp;
    this.updateManifest = mnCollectionsService.stream.updateManifest;
  }

  ngOnInit() {
    this.form
      .setFormGroup({name: "", bucketName: this.bucketName})
      .setPostRequest(this.addScopeHttp)
      .success(() => {
        this.updateManifest.next();
        this.activeModal.close();
      });
  }
}
