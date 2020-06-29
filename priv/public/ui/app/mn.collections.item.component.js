import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js"
import {takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {Subject} from "/ui/web_modules/rxjs.js";
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';
import {MnCollectionsDeleteItemComponent} from './mn.collections.delete.item.component.js';

export {MnCollectionsItemComponent};

class MnCollectionsItemComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-collections-item",
      templateUrl: "app/mn.collections.item.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "collection",
        "scopeName",
        "bucketName"
      ]
    })
  ]}

  static get parameters() { return [
    MnCollectionsService,
    MnPermissions,
    NgbModal
  ]}

  constructor(mnCollectionsService, mnPermissions, modalService) {
    super();

    var clickDeleteCollection = new Subject();

    clickDeleteCollection
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => {
        var ref = modalService.open(MnCollectionsDeleteItemComponent);
        ref.componentInstance.scopeName = this.scopeName;
        ref.componentInstance.bucketName = this.bucketName;
        ref.componentInstance.collectionName = this.collection.name;
      });

    this.clickDeleteCollection = clickDeleteCollection;
    this.permissions = mnPermissions.export;
  }
}
