import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js"
import {takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {Subject} from "/ui/web_modules/rxjs.js";

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';
import {MnCollectionsDeleteScopeComponent} from './mn.collections.delete.scope.component.js';

export {MnCollectionsItemComponent};

class MnCollectionsItemComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-collections-item",
      templateUrl: "app/mn.collections.item.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "scope",
        "bucketName"
      ]
    })
  ]}

  static get parameters() { return [
    MnCollectionsService,
    NgbModal
  ]}

  constructor(mnCollectionsService, modalService) {
    super();

    var clickDeleteScope = new Subject();

    clickDeleteScope
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => {
        var ref = modalService.open(MnCollectionsDeleteScopeComponent);

        ref.componentInstance.scopeName = this.scope.name;
        ref.componentInstance.bucketName = this.bucketName;
      });

    this.clickDeleteScope = clickDeleteScope;
  }
}
