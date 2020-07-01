import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {FormBuilder} from "/ui/web_modules/@angular/forms.js";
import {UIRouter} from "/ui/web_modules/@uirouter/angular.js";
import {pluck, take, filter, switchMap, distinctUntilChanged,
        switchMapTo, map, shareReplay, takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {combineLatest, Subject, timer} from "/ui/web_modules/rxjs.js";
import {equals, compose, not} from "/ui/web_modules/ramda.js";
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js";
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';
import {MnBucketsService} from './mn.buckets.service.js';
import {MnCollectionsAddScopeComponent} from './mn.collections.add.scope.component.js';
import {MnCollectionsAddItemComponent} from './mn.collections.add.item.component.js';

import { MnInputFilterService } from './mn.input.filter.service.js';

export {MnCollectionsComponent};

class MnCollectionsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.collections.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnCollectionsService,
    MnPermissions,
    MnBucketsService,
    UIRouter,
    NgbModal,
    FormBuilder,
    MnInputFilterService
  ]}

  constructor(mnCollectionsService, mnPermissions, mnBucketsService,
              uiRouter, modalService, formBuilder, mnInputFilterService) {
    super();

    var clickAddScope = new Subject();
    var clickAddCollection = new Subject();

    var bucketSelect = formBuilder.group({name: null});

    var setBucket = (v) =>
        bucketSelect.patchValue({name: v});

    var setBucketUrlParam = (v, location) =>
        uiRouter.stateService.go('.', {collectionsBucket: v.name}, {
          notify: false,
          location: location || true
        });

    var filterBuckets = buckets => Object
        .keys(buckets)
        .filter(bucketName =>
                mnPermissions.export.cluster.bucket[bucketName] &&
                mnPermissions.export.cluster.bucket[bucketName].collections.read);

    var getBuckets =
        mnBucketsService.stream.getBucketsByName.pipe(map(filterBuckets));

    var getBucketUrlParam =
        uiRouter.globals.params$.pipe(pluck("collectionsBucket"),
                                      distinctUntilChanged());
    var getBucketUrlParamDefined =
        getBucketUrlParam
        .pipe(filter(compose(not, equals(undefined))));

    getBucketUrlParam
      .pipe(
        filter(equals(undefined)),
        switchMapTo(getBuckets),
        pluck(0),
        take(1))
      .subscribe(v => setBucketUrlParam({name: v}, "replace"));

    getBucketUrlParamDefined
      .pipe(take(1))
      .subscribe(setBucket);

    bucketSelect.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(setBucketUrlParam);

    var scopes =
        combineLatest(getBucketUrlParamDefined,
                      mnCollectionsService.stream.updateManifest,
                      timer(0, 5000))
        .pipe(switchMap(([bucket]) => mnCollectionsService.getManifest(bucket)),
              pluck("scopes"),
              shareReplay({refCount: true, bufferSize: 1}));

    clickAddScope
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => {
        var ref = modalService.open(MnCollectionsAddScopeComponent);
        ref.componentInstance.bucketName = bucketSelect.get("name").value;
      });

    clickAddCollection
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => {
        var ref = modalService.open(MnCollectionsAddItemComponent);
        ref.componentInstance.bucketName = bucketSelect.get("name").value;
      });

    this.filter = mnInputFilterService.create(scopes);
    this.buckets = getBuckets;
    this.bucketSelect = bucketSelect;
    this.scopes = scopes;
    this.clickAddScope = clickAddScope;
    this.clickAddCollection = clickAddCollection;
  }

  trackByFn(_, scope) {
    return scope.name;
  }
}
