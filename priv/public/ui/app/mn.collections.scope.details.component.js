import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {Subject} from "/ui/web_modules/rxjs.js";

import {MnLifeCycleHooksToStream, DetailsHashObserver} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';

export {MnCollectionsScopeDetailsComponent};

class MnCollectionsScopeDetailsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-collections-scope-details",
      templateUrl: "app/mn.collections.scope.details.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "scope",
        "bucketName"
      ]
    })
  ]}

  static get parameters() { return [
    MnCollectionsService
  ]}

  constructor(mnCollectionsService) {
    super();
  }

  trackByFn(_, collection) {
    return collection.uid;
  }
}
