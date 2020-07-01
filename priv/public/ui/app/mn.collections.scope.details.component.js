import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {pluck} from '/ui/web_modules/rxjs/operators.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnInputFilterService} from './mn.input.filter.service.js';

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
    MnInputFilterService
  ]}

  constructor(mnInputFilterService) {
    super();
    this.mnInputFilterService = mnInputFilterService;
  }

  ngOnInit() {
    this.filter = this.mnInputFilterService.create(
      this.mnOnChanges.pipe(pluck("scope", "currentValue", "collections"))
    );
  }

  trackByFn(_, collection) {
    return collection.uid;
  }
}
