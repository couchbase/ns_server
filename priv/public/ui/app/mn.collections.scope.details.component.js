/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '../web_modules/@angular/core.js'
import {pluck} from '../web_modules/rxjs/operators.js';
import {shareReplay} from '../web_modules/rxjs/operators.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnHelperService} from './mn.helper.service.js';

import {loadHTML} from './mn.core.js';
let template = await loadHTML('./mn.collections.scope.details.html', import.meta.url);

export {MnCollectionsScopeDetailsComponent};

class MnCollectionsScopeDetailsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-collections-scope-details",
      template: template,
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "mnCollectionsStatsPoller",
        "scope",
        "scopeName",
        "bucketName",
        "statusClass"
      ]
    })
  ]}

  static get parameters() { return [
    MnHelperService
  ]}

  constructor(mnHelperService) {
    super();
    this.mnHelperService = mnHelperService;
    this.filter = mnHelperService.createFilter(this);
    this.sorter = mnHelperService.createSorter('name');
  }

  ngOnInit() {
    this.collections =
      this.mnOnChanges.pipe(pluck("scope", "currentValue", "collections"),
                            this.filter.pipe,
                            this.sorter.pipe,
                            shareReplay({refCount: true, bufferSize: 1}));
    this.paginator =
      this.mnHelperService.createPagenator(this,
                                           this.collections,
                                           "collsPage",
                                           this.scopeName);
  }

  trackByFn(_, collection) {
    return this.bucketName + collection.uid + collection.name;
  }
}
