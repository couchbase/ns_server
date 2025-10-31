/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {UIRouter} from '@uirouter/angularjs';
import {combineLatest} from 'rxjs';
import {pluck, map, withLatestFrom, shareReplay} from 'rxjs/operators';

import {MnPermissions} from './ajs.upgraded.providers.js';
import {MnLifeCycleHooksToStream, DetailsHashObserver} from './mn.core.js';
import {MnTasksService} from './mn.tasks.service.js';
import {MnBucketsService} from './mn.buckets.service.js';
import {MnAdminService} from './mn.admin.service.js';
import template from "./mn.bucket.item.html";

export {MnBucketItemComponent};

class MnBucketItemComponent extends MnLifeCycleHooksToStream {
  static get annotations() {
    return [
      new Component({
        selector: 'mn-bucket-item',
        template,
        inputs: [
          'bucket'
        ],
        changeDetection: ChangeDetectionStrategy.OnPush
      })
    ];
  }

  static get parameters() {
    return [
      UIRouter,
      MnTasksService,
      MnBucketsService,
      MnAdminService,
      MnPermissions
    ];
  }

  constructor(uiRouter, mnTasksService, mnBucketsService, mnAdminService, mnPermissions) {
    super();

    this.uiRouter = uiRouter;
    this.permissions = mnPermissions.stream;
    this.compatVersion70 = mnAdminService.stream.compatVersion70;

    let currentBucket = this.mnOnChanges
      .pipe(pluck('bucket', 'currentValue'));

    this.bucketNodes = currentBucket
      .pipe(pluck('nodes'));

    this.residentRatio = currentBucket
      .pipe(map(mnBucketsService.getResidentRatio));

    this.statusClass = currentBucket
      .pipe(map(v => mnBucketsService.getNodesStatusClass(v)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.nodesCountByStatusMessage = this.bucketNodes
      .pipe(map(v => mnBucketsService.getNodesCountByStatus(v)),
            map(v => mnBucketsService.getNodesCountByStatusMessage(v)),
            shareReplay({refCount: true, bufferSize: 1}));

    let tasksWarmingUp = mnTasksService.stream.tasksWarmingUp;

    this.warmUpProgress = tasksWarmingUp
      .pipe(withLatestFrom(currentBucket),
            map(v => mnBucketsService.getWarmUpProgress(v)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.showWarmUpProgress =
      combineLatest(this.warmUpProgress,
                    this.permissions)
      .pipe(map(this.isWarmUpProgressVisible.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.storageBackend = currentBucket
      .pipe(map(v => mnBucketsService.prepareStorageBackendText(v)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.storageBackendChangePending = currentBucket
      .pipe(map(v => mnBucketsService.isStorageBackendChangePending(v)));

    this.nodesNrStorageBackendPending = currentBucket
      .pipe(map(v => mnBucketsService.getNodesNrStorageBackendPending(v)));

    this.nodesNrStorageBackendPendingDone = currentBucket
      .pipe(map(v => mnBucketsService.getNodesNrStorageBackendPendingDone(v)));

    this.evictionPolicy = currentBucket
      .pipe(map(v => mnBucketsService.prepareEjectionMethodText(v)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.evictionPolicyChangePending = currentBucket
      .pipe(map(v => mnBucketsService.isEvictionPolicyChangePending(v)));

    this.nodesNrEvictionPolicyPendingDone = currentBucket
      .pipe(map(v => mnBucketsService.getNodesNrEvictionPolicyPendingDone(v)));

    this.nodesNrEvictionPolicyPending = currentBucket
      .pipe(map(v => mnBucketsService.getNodesNrEvictionPolicyPending(v)));
  }

  ngOnInit() {
    this.detailsHashObserver =
      new DetailsHashObserver(this.uiRouter, this, 'openedBuckets', this.bucket.name);

    let toggleClassConditions =
      combineLatest(this.detailsHashObserver.stream.isOpened,
                    this.statusClass,
                    this.showWarmUpProgress);

    this.sectionClass = toggleClassConditions
      .pipe(map((params) => this.isWholeColorHeight(params) ? params[1] : ''));

    this.tableClass = toggleClassConditions
      .pipe(map((params) => this.isWholeColorHeight(params) ? '' : params[1]));

    this.showDetails =
      combineLatest(this.detailsHashObserver.stream.isOpened,
                    this.permissions)
      .pipe(map(this.isDetailsVisible.bind(this)));

    this.showDocumentsLink = this.permissions
      .pipe(map(this.isDocumentsLinkVisible.bind(this)));

    this.showScopesAndCollectionsLink =
      combineLatest(this.permissions,
                    this.compatVersion70)
      .pipe(map(this.isScopesAndCollectionsLinkVisible.bind(this)));
  }

  isDetailsVisible([isOpened, permissions]) {
    let bucketPerm = permissions.cluster.bucket[this.bucket.name];
    return isOpened && bucketPerm && bucketPerm.settings.read;
  }

  isDocumentsLinkVisible(permissions) {
    let name = this.bucket.name + ":.:.";
    let bucketPerm = permissions.cluster.collection[name];
    return bucketPerm && bucketPerm.data.docs.read && bucketPerm.collections.read;
  }

  isScopesAndCollectionsLinkVisible([permissions, compat70]) {
    let bucketPerm = permissions.cluster.collection[this.bucket.name + ':.:.'];

    return compat70 && bucketPerm && bucketPerm.collections.read;
  }

  isWarmUpProgressVisible([warmupProgress, permissions]) {
    return warmupProgress !== false && permissions.cluster.tasks.read;
  }

  isWholeColorHeight([isOpened, statusClass, isWarmup]) {
    return isOpened || statusClass !== 'dynamic_healthy' || isWarmup;
  }
}
