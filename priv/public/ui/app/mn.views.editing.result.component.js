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
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { take, pluck, filter, map, catchError,
         withLatestFrom, takeUntil, startWith,
         shareReplay } from 'rxjs/operators';
import { Subject, combineLatest, of } from 'rxjs';
import { reject, equals, is } from 'ramda';

import { MnFormService } from './mn.form.service.js';
import { MnViewsEditingService } from './mn.views.editing.service.js';
import { MnAdminService } from './mn.admin.service.js';
import { MnDocumentsService } from './mn.documents.service.js';

import { viewsPerPageLimit } from './constants/constants.js';

export { MnViewsEditingResultComponent };

class MnViewsEditingResultComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "views-editing-result",
      templateUrl: "app/mn.views.editing.result.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnFormService,
    UIRouter,
    MnViewsEditingService,
    MnAdminService,
    MnDocumentsService
  ]}

  constructor(mnFormService, uiRouter, mnViewsEditingService, mnAdminService, mnDocumentsService) {
    super();

    this.uiRouter = uiRouter;
    this.capiBase = mnAdminService.stream.capiBase;
    this.mnDocumentsService = mnDocumentsService;

    this.getViewResult = mnViewsEditingService.stream.getViewResult.response;

    this.ddocumentId = uiRouter.globals.params$
      .pipe(pluck('ddocumentId'));

    this.viewId = uiRouter.globals.params$
      .pipe(pluck('viewId'));

    this.commonBucket = uiRouter.globals.params$
      .pipe(pluck('commonBucket'));

    this.pageNumber = uiRouter.globals.params$
      .pipe(pluck('pageNumber'));

    this.fullSet = uiRouter.globals.params$
      .pipe(pluck('full_set'));

    this.rows = this.getViewResult
      .pipe(map(result => {
        if (result.status == "500") {
          return [];
        }

        return result.rows;
      }));

    this.showViewResultMessage =
      combineLatest(this.pageNumber, this.rows)
      .pipe(map(([pageNumber, rows]) => !is(Number, pageNumber) && !rows.length));

    this.defaultFormGroup = {
      conflicts: null,
      descending: null,
      startKey: null,
      endKey: null,
      startKeyDocId: null,
      endKeyDocId: null,
      stale: "false",
      group: null,
      group_level: null,
      inclusive_end: true,
      connection_timeout: 60000,
      key: null,
      keys: null,
      reduce: ""
    };

    this.form = mnFormService.create(this)
      .setFormGroup(this.defaultFormGroup)
      .hasNoPostRequest();

    this.params = this.form.submit
      .pipe(startWith('stale=false&inclusive_end=true&connection_timeout=60000'),
            map(() => this.generateParamsString(this.form.group.value)));

    this.isDevelopmentDocument = this.ddocumentId
      .pipe(map(id => id.includes('_design/dev_')));

    this.pageNumber
      .pipe(take(1),
            filter(n => is(Number, n)),
            withLatestFrom(this.pageNumber,
                           this.params,
                           this.ddocumentId,
                           this.viewId,
                           this.commonBucket,
                           this.fullSet))
      .subscribe(this.onClickResult.bind(this));

    this.paginateParams = this.pageNumber
      .pipe(map(pageNumber => {
        if (!pageNumber) {
          return [0, viewsPerPageLimit];
        }

        let upperRange = viewsPerPageLimit + (pageNumber * viewsPerPageLimit);
        let lowerRange = upperRange - viewsPerPageLimit;

        return [lowerRange, upperRange];
      }));

    this.maxPageNumber =
      combineLatest(this.rows,
                    this.pageNumber)
      .pipe(map(([rows, pageNumber]) => {
        if (!is(Number, pageNumber) || !rows.length) {
          return 0;
        }

        return Math.floor(rows.length / viewsPerPageLimit);
      }));

    this.url =
      combineLatest(this.params,
                    this.ddocumentId,
                    this.viewId,
                    this.commonBucket)
      .pipe(map(([params, ddocumentId, viewId, commonBucket]) =>
          this.buildFullUrl(params, ddocumentId, viewId, commonBucket)));

    this.paginatedRows =
      combineLatest(this.rows,
                    this.paginateParams)
      .pipe(map(([rows, range]) => {
        return rows.slice(range[0], range[1]);
      }));

    this.disablePrev = this.pageNumber
      .pipe(map(this.disablePrev.bind(this)));

    this.disableNext =
      combineLatest(this.rows,
                    this.pageNumber,
                    this.maxPageNumber)
      .pipe(map(this.disableNext.bind(this)));

    this.showNoResults =
      combineLatest(this.rows, this.pageNumber)
      .pipe(map(this.showNoResults.bind(this)));

    this.clickResult = new Subject();
    this.clickResult
      .pipe(withLatestFrom(this.pageNumber,
                           this.params,
                           this.ddocumentId,
                           this.viewId,
                           this.commonBucket,
                           this.fullSet),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.onClickResult.bind(this));

    this.clickNextPage = new Subject();
    this.clickNextPage
      .pipe(withLatestFrom(this.pageNumber),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.onNextPage.bind(this));

    this.clickPrevPage = new Subject();
    this.clickPrevPage
      .pipe(withLatestFrom(this.pageNumber),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.onPrevPage.bind(this));

    this.clickLoadDocument = new Subject();
    this.clickLoadDocument
      .pipe(withLatestFrom(this.commonBucket))
    .subscribe(this.loadDocument.bind(this))
  }

  showNoResults([rows, pageNumber]) {
    return is(Number, pageNumber) && !rows.length;
  }

  generateParamsString(value) {
    let params = reject(equals(null))(value);
    params = reject(equals(""))(params);

    return new URLSearchParams(params).toString();
  }

  disablePrev(pageNumber) {
    return !is(Number, pageNumber) || (pageNumber == 0);
  }

  disableNext([rows, pageNumber, maxPage]) {
    return !rows.length || (pageNumber >= maxPage);
  }

  onNextPage([, currentPage]) {
    this.uiRouter.stateService.go('.', { pageNumber: currentPage + 1 } , { notify: false });
   }

  onPrevPage([, currentPage]) {
    this.uiRouter.stateService.go('.', { pageNumber: currentPage - 1 } , { notify: false });
  }

  onClickResult([, pageNumber, params, ddocumentId, viewId, commonBucket, fullSet]) {
    if (!pageNumber) {
      this.uiRouter.stateService.go('.', { pageNumber: 0 } , { notify: false });
    }

    this.getViewResult.next(this.buildFullUrl(params, ddocumentId, viewId, commonBucket, fullSet));
  }

  buildViewUrl(ddocumentId, viewId, commonBucket) {
    if (ddocumentId.slice(0, "_design/".length) === "_design/") {
      ddocumentId = "_design/" + encodeURIComponent(ddocumentId.slice("_design/".length));
    }

    if (ddocumentId.slice(0, "_local/".length) === "_local/") {
      ddocumentId = "_local/" + encodeURIComponent(ddocumentId.slice("_local/".length));
    }

    return encodeURIComponent(commonBucket) + "/" + ddocumentId + "/_view/" + encodeURIComponent(viewId);
  }

  buildFullUrl(params, ddocumentId, viewId, commonBucket, fullSet) {
    if (fullSet) {
      params += "&full_set=true";
    }

    return '/couchBase/' + this.buildViewUrl(ddocumentId, viewId, commonBucket) + '?' + params;
  }

  loadDocument([id, bucket]) {
    this.mnDocumentsService.stream.getManualDocument.next([id, bucket]);
  }
}
