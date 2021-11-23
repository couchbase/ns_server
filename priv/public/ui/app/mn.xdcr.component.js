/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {Subject} from 'rxjs';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {takeUntil, map, pluck, distinctUntilChanged,
        merge, mapTo, startWith, combineLatest, first,
        shareReplay} from 'rxjs/operators';

import {MnPermissions} from './ajs.upgraded.providers.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnXDCRService} from './mn.xdcr.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnTasksService} from './mn.tasks.service.js';
import {MnHelperService} from './mn.helper.service.js';

import {MnXDCRAddRefComponent} from "./mn.xdcr.add.ref.component.js";

export { MnXDCRComponent };

class MnXDCRComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "app/mn.xdcr.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnPermissions,
    MnXDCRService,
    MnPoolsService,
    MnTasksService,
    MnHelperService,
    NgbModal
  ]}

  constructor(mnPermissions, mnXDCRService, mnPoolsService, mnTasksService,
              mnHelperService, modalService) {
    super();

    var onAddReference = new Subject();
    onAddReference
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => modalService.open(MnXDCRAddRefComponent));

    var referenceSorter = mnHelperService.createSorter("name");

    this.tasksXDCR = mnTasksService.stream.tasksXDCR;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.permissions = mnPermissions.stream;

    let getRemoteClustersFiltered =
        mnXDCRService.stream.getRemoteClustersFiltered;

    let hasPermissionsToWrite =
        this.permissions.pipe(map((p) => {
          return p.cluster.xdcr.settings.read &&
            p.cluster.xdcr.settings.write &&
            p.cluster.bucket['.'].xdcr.write;
        }), distinctUntilChanged());

    let isTasksXDCROpen = this.tasksXDCR
        .pipe(first(),
              mapTo(true),
              startWith(false));
    let isGetRemoteClustersOpen = getRemoteClustersFiltered
        .pipe(first(),
              mapTo(true),
              startWith(false),
              shareReplay(1));
    let hasReferences = getRemoteClustersFiltered
        .pipe(pluck("length"),
              map(Boolean),
              startWith(false),
              shareReplay(1));

    this.isLoading = isGetRemoteClustersOpen
      .pipe(merge(isTasksXDCROpen),
            mapTo(false),
            startWith(true),
            distinctUntilChanged());

    let isGetRemoteClustersOpenAndHasNoReferencesAndEnterpriseReady =
        isGetRemoteClustersOpen
        .pipe(combineLatest(hasReferences, this.isEnterprise),
              map(([isGetRemoteClustersOpen, hasReferences,]) =>
                isGetRemoteClustersOpen && !hasReferences));

    this.isNoRemoteClustersDefinedVisible =
      isGetRemoteClustersOpenAndHasNoReferencesAndEnterpriseReady
      .pipe(startWith(false));

    this.isOutgoingReplicationHidden =
      isGetRemoteClustersOpenAndHasNoReferencesAndEnterpriseReady
      .pipe(startWith(true));

    this.isAddReplicationBtnHidden = hasReferences
      .pipe(combineLatest(hasPermissionsToWrite),
            map(([hasReferences, hasPermissions]) => !hasReferences || !hasPermissions),
            shareReplay(1));

    this.isNotPermittedWarningVisible = this.isEnterprise
      .pipe(combineLatest(hasReferences),
            map(([isEnterprise, hasReferences]) => !isEnterprise && hasReferences));

    this.getRemoteClustersSorted = getRemoteClustersFiltered
      .pipe(referenceSorter.pipe);

    this.onAddReference = onAddReference;
    this.referenceSorter = referenceSorter;

    this.getChangesLeftTotal = mnXDCRService.stream.getChangesLeftTotal;

  }

  trackByFn(_, row) {
    return row.name;
  }

  tasksTrackByFn(_, row) {
    return row.id;
  }
}
