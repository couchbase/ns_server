/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { Component, ChangeDetectionStrategy } from '@angular/core';
import { UIRouter } from '@uirouter/angular';
import { startWith, map, pluck, takeUntil, withLatestFrom, distinctUntilChanged } from 'rxjs/operators';
import { Subject, combineLatest } from "rxjs";
import { NgbModal } from "@ng-bootstrap/ng-bootstrap";
import { intersection } from 'ramda';
import { MnLifeCycleHooksToStream } from './mn.core.js';

import { MnFormService } from './mn.form.service.js';
import { MnPermissions } from './ajs.upgraded.providers.js';
import { MnRouterService } from './mn.router.service.js';
import { MnViewsListService } from './mn.views.list.service.js';
import { MnBucketsService } from './mn.buckets.service.js';

import { MnViewsCreateDialogComponent } from './mn.views.create.dialog.component.js';

export { MnViewsListComponent };

class MnViewsListComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-views-list",
      templateUrl: "app/mn.views.list.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    UIRouter,
    MnPermissions,
    MnFormService,
    MnViewsListService,
    MnRouterService,
    MnBucketsService,
    NgbModal
  ]}

  constructor(uiRouter, mnPermissions, mnFormService, mnViewsListService, mnRouterService, mnBucketsService, modalService) {
    super();

    this.permissions = mnPermissions.stream;
    this.uiRouter = uiRouter;

    this.getDdocsStatus = mnViewsListService.stream.getDdocsStatus;

    this.getDdocsByType = mnViewsListService.stream.getDdocsByType
      .pipe(startWith({ development: [], production: [] }));

    /* Stream to prevent magma buckets displaying in the bucket dropdown,
     * as they aren't filtered out in the views read permissions. */
    this.allowedBuckets = mnBucketsService.stream.bucketsMembaseCouchstore;
    this.bucketNames = this.permissions
      .pipe(map(p => {
        if (Object.keys(p.bucketNames).length) {
          return p.bucketNames['.views!read'];
        } else {
          return [];
        }
      }));

    this.buckets =
      combineLatest(this.bucketNames,
                    this.allowedBuckets)
      .pipe(map(([bucketNames, allowed]) => intersection(bucketNames, allowed.map(bucket => bucket.name))),
            startWith([]));

    this.commonBucket = uiRouter.globals.params$
      .pipe(pluck('commonBucket'));

    this.type = uiRouter.globals.params$
      .pipe(pluck('type'));

    this.form = mnFormService.create(this)
      .setFormGroup({ item: null })
      .setSource(mnViewsListService.stream.getDdocs);

    combineLatest(this.commonBucket,
                  this.bucketNames)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(([bucket, existingBuckets]) => {
        if (existingBuckets.includes(bucket)) {
          return this.form.group.get('item').patchValue(bucket);
        } else {
          return this.form.group.get('item').patchValue(null);
        }
      });

    this.getDdocsOfType =
      combineLatest(this.getDdocsByType,
                    this.type)
      .pipe(map(([ddocs, type]) => ddocs[type]));

    this.hasCreatePermission = this.permissions
      .pipe(pluck('cluster', 'buckets', 'create'));

    this.hasWritePermission =
      combineLatest(this.permissions,
                    this.commonBucket)
      .pipe(map(this.hasWritePermission.bind(this)));

    this.hasReadPermission =
      combineLatest(this.permissions,
                    this.commonBucket)
      .pipe(map(this.hasReadPermission.bind(this)));

    this.hasDevDdocs = this.getDdocsByType
      .pipe(startWith({ development: [] }),
        map(ddocs => !!ddocs.development.length));

    this.hasProdDdocs = this.getDdocsByType
      .pipe(startWith({ production: [] }),
        map(ddocs => !!ddocs.production.length));

    this.showErrors = this.getDdocsStatus
      .pipe(map(this.showErrors.bind(this)));

    this.showZeroContent =
      combineLatest(this.getDdocsByType,
                    this.type,
                    this.buckets)
      .pipe(map(this.showZeroContent.bind(this)));

    this.isDevelopmentViews = this.type
      .pipe(map(this.isDevelopmentViews.bind(this)));

    /* bucket dropdown */

    this.bucketDropdown =
      mnRouterService.createBucketDropdown(this.buckets);

    this.bucketDropdown.getBucketUrlParamDefinedChanged
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.setBucket.bind(this));

    this.form.group.get("item").valueChanges
      .pipe(distinctUntilChanged(),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.setBucketUrlParam.bind(this));

    this.createDialog = new Subject();
    this.createDialog
      .pipe(takeUntil(this.mnOnDestroy),
            withLatestFrom(this.getDdocsOfType))
      .subscribe(([, ddocs]) => {
        let ref = modalService.open(MnViewsCreateDialogComponent);
        ref.componentInstance.ddocs = ddocs;
      })
  }

  hasWritePermission([permissions, bucket]) {
    return permissions.cluster.bucket[bucket] &&
      permissions.cluster.bucket[bucket].views.write;
  }

  hasReadPermission([permissions, bucket]) {
    return permissions.cluster.bucket[bucket] &&
      permissions.cluster.bucket[bucket].views.read;
  }

  setBucket(item) {
    return this.form.group.patchValue({ item });
  }

  setBucketUrlParam(name, location) {
    return this.uiRouter.stateService.go('.', {
      commonBucket: name ? name : null
    }, {
      notify: false,
      location: location || true
    });
  }

  showErrors(ddocStatus) {
    return ddocStatus !== 200;
  }

  showZeroContent([ddocsByType, type, buckets]) {
    return buckets.length && ddocsByType[type].length;
  }

  isDevelopmentViews(type) {
    return type === "development";
  }
}
