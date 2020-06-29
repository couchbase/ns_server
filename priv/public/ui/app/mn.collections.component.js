import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {FormGroup, FormControl} from "/ui/web_modules/@angular/forms.js";
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
    NgbModal
  ]}

  constructor(mnCollectionsService, mnPermissions, mnBucketsService,
              uiRouter, modalService) {
    super();

    var clickAddScope = new Subject();
    var clickAddCollection = new Subject();

    var bucketSelect = new FormGroup({
      name: new FormControl()
    });

    var setBucket = (v) =>
        bucketSelect.patchValue({name: v});

    var setBucketUrlParam = (v) =>
        uiRouter.stateService.go('.', {collectionsBucket: v.name}, {notify: false});

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
      .subscribe(setBucket);

    getBucketUrlParamDefined
      .pipe(take(1))
      .subscribe(setBucket);

    bucketSelect.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(setBucketUrlParam);

    var manifest =
      combineLatest(getBucketUrlParamDefined,
                    mnCollectionsService.stream.updateManifest,
                    timer(0, 5000))
        .pipe(switchMap(([bucket]) => mnCollectionsService.getManifest(bucket)),
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

    this.buckets = getBuckets;
    this.bucketSelect = bucketSelect;
    this.manifest = manifest;
    this.clickAddScope = clickAddScope;
    this.clickAddCollection = clickAddCollection;
  }

  trackByFn(_, scope) {
    return scope.name;
  }
}
