import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js"
import {takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {Subject} from "/ui/web_modules/rxjs.js";
import {UIRouter} from "/ui/web_modules/@uirouter/angular.js";
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream, DetailsHashObserver} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';
import {MnCollectionsDeleteScopeComponent} from './mn.collections.delete.scope.component.js';

export {MnCollectionsScopeComponent};

class MnCollectionsScopeComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-collections-scope",
      templateUrl: "app/mn.collections.scope.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "scope",
        "bucketName",
        "statusClass"
      ]
    })
  ]}

  static get parameters() { return [
    MnCollectionsService,
    MnPermissions,
    NgbModal,
    UIRouter
  ]}

  constructor(mnCollectionsService, mnPermissions, modalService, uiRouter) {
    super();

    var clickDeleteScope = new Subject();

    clickDeleteScope
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => {
        var ref = modalService.open(MnCollectionsDeleteScopeComponent);
        ref.componentInstance.scopeName = this.scope.name;
        ref.componentInstance.bucketName = this.bucketName;
      });

    this.uiRouter = uiRouter;
    this.clickDeleteScope = clickDeleteScope;
    this.permissions = mnPermissions.export;
  }

  ngOnInit() {
    var detailsHashObserver =
        new DetailsHashObserver(this.uiRouter, this, "scopeDetails", this.scope.name);
    this.detailsHashObserver = detailsHashObserver;
  }
}
