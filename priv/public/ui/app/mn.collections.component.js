import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {FormGroup, FormControl} from "/ui/web_modules/@angular/forms.js";
import {UIRouter} from "/ui/web_modules/@uirouter/angular.js";
import {pluck, take, filter, switchMap,
        switchMapTo, map, shareReplay} from '/ui/web_modules/rxjs/operators.js';
import {combineLatest, timer} from "/ui/web_modules/rxjs.js";
import {equals, compose, not} from "/ui/web_modules/ramda.js";

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';
import {MnPermissionsService} from './mn.permissions.service.js';
import {MnBucketsService} from './mn.buckets.service.js';

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
    MnPermissionsService,
    MnBucketsService,
    UIRouter
  ]}

  constructor(mnCollectionsService, mnPermissionsService, mnBucketsService, uiRouter) {
    super();

    var bucketSelect = new FormGroup({
      name: new FormControl()
    });

    var setBucket = (v) =>
        bucketSelect.patchValue({name: v});

    var setBucketUrlParam = (v) =>
        uiRouter.stateService.go('.', {collectionsBucket: v.name}, {notify: false});

    var filterBuckets = ([buckets, permissions]) => Object
        .keys(buckets)
        .filter(bucketName =>
                permissions[`cluster.bucket[${bucketName}].collections!read`]
                && buckets[bucketName].bucketType !== "memcached");

    var getBuckets =
        combineLatest(mnBucketsService.stream.getBucketsByName,
                      mnPermissionsService.stream.getBucketsPermissions)
        .pipe(map(filterBuckets));

    var getBucketUrlParam =
        uiRouter.globals.params$.pipe(pluck("collectionsBucket"))

    getBucketUrlParam
      .pipe(
        filter(equals(undefined)),
        switchMapTo(getBuckets),
        pluck(0),
        take(1))
      .subscribe(setBucket);

    getBucketUrlParam
      .pipe(filter(compose(not, equals(undefined))), take(1))
      .subscribe(setBucket);

    bucketSelect.valueChanges
      .subscribe(setBucketUrlParam);

    var manifest =
      combineLatest(getBucketUrlParam,
                    mnCollectionsService.stream.updateManifest,
                    timer(0, 5000))
        .pipe(switchMap(([bucket]) => mnCollectionsService.getManifest(bucket)),
              shareReplay({refCount: true, bufferSize: 1}));

    this.buckets = getBuckets;
    this.bucketSelect = bucketSelect;
    this.manifest = manifest;
  }

  trackByFn(_, scope) {
    return scope.name;
  }
}
