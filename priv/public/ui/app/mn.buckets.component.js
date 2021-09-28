/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {Subject, BehaviorSubject, combineLatest} from 'rxjs';
import {map, takeUntil, withLatestFrom} from 'rxjs/operators';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';

import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {MnBucketsService} from "./mn.buckets.service.js";
import {MnHelperService} from './mn.helper.service.js';
import {MnAdminService} from './mn.admin.service.js';
import {MnPermissions} from './ajs.upgraded.providers.js';

import {MnBucketDialogComponent} from './mn.bucket.dialog.component.js';
import {MnBucketFullDialogComponent} from './mn.bucket.full.dialog.component.js';

export {MnBucketsComponent};

class MnBucketsComponent extends MnLifeCycleHooksToStream {
  static get annotations() {
    return [
      new Component({
        templateUrl: "app/mn.buckets.html",
        changeDetection: ChangeDetectionStrategy.OnPush
      })
    ]
  }

  static get parameters() {
    return [
      MnBucketsService,
      MnHelperService,
      MnAdminService,
      MnPermissions,
      NgbModal
    ]
  }

  constructor(mnBucketsService, mnHelperService, mnAdminService, mnPermissions, modalService) {
    super();

    this.modalService = modalService;
    this.filter = mnHelperService.createFilter(this);
    this.sorter = mnHelperService.createSorter("name");

    this.buckets = mnBucketsService.stream.getBucketsPool;

    this.filteredBuckets = this.buckets
      .pipe(this.filter.pipe,
            this.sorter.pipe);

    this.isRebalancing = mnAdminService.stream.isRebalancing;
    this.maxBucketCount = mnAdminService.stream.maxBucketCount;

    this.onAddBucketClick = new Subject();
    this.onAddBucketClick
      .pipe(withLatestFrom(mnAdminService.stream.storageTotals),
            takeUntil(this.mnOnDestroy))
      .subscribe(([,storageTotals]) => {
        let ram = storageTotals.ram;
        if (!ram || ram.quotaTotal === ram.quotaUsed) {
          this.modalService.open(MnBucketFullDialogComponent);
        } else {
          this.modalService.open(MnBucketDialogComponent);
        }
      });

    this.maxBucketCountReached =
      combineLatest(this.filteredBuckets,
                    mnAdminService.stream.maxBucketCount)
      .pipe(map(([buckets, maxBuckets]) => buckets.length >= maxBuckets));

    this.visibleMaxBucketCountWarning = new BehaviorSubject(true);
    this.showMaxBucketWarning =
      combineLatest(this.maxBucketCountReached,
                    this.visibleMaxBucketCountWarning)
      .pipe(map(([maxReached, isVisible]) => maxReached && isVisible));

    this.isNewBucketAllowed =
      combineLatest(mnPermissions.stream,
                    this.maxBucketCountReached,
                    mnAdminService.stream.isRebalancing)
      .pipe(map(mnBucketsService.isNewBucketAllowed.bind(mnBucketsService)));
  }

  trackBy(index, bucket) {
    return bucket.name;
  }

}