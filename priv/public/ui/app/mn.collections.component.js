import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {FormBuilder} from "/ui/web_modules/@angular/forms.js";
import {UIRouter} from "/ui/web_modules/@uirouter/angular.js";
import {pluck, filter, switchMap, distinctUntilChanged, withLatestFrom,
        shareReplay, takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {combineLatest, Subject, timer} from "/ui/web_modules/rxjs.js";
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js";
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';
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
    UIRouter,
    NgbModal,
    FormBuilder,
    MnInputFilterService
  ]}

  constructor(mnCollectionsService, mnPermissions,
              uiRouter, modalService, formBuilder, mnInputFilterService) {
    super();

    var clickAddScope = new Subject();
    var clickAddCollection = new Subject();

    var bucketSelect = formBuilder.group({name: null});

    var setBucket = (v) =>
        bucketSelect.patchValue({name: v});

    var setBucketUrlParam = (name, location) =>
        uiRouter.stateService.go('.', {collectionsBucket: name ? name : null}, {
          notify: false,
          location: location || true
        });

    var getBuckets =
        mnCollectionsService.stream.collectionBuckets;

    var getBucketUrlParam =
        uiRouter.globals.params$.pipe(pluck("collectionsBucket"),
                                      distinctUntilChanged());
    var getBucketUrlParamDefined =
        combineLatest(
          getBucketUrlParam,
          getBuckets
        ).pipe(filter(([param, buckets]) => param && buckets.includes(param)),
               pluck(0),
               distinctUntilChanged());

    var bucketsWithParams =
        getBuckets.pipe(withLatestFrom(getBucketUrlParam));

    getBucketUrlParamDefined
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(setBucket);

    bucketSelect.get("name").valueChanges
      .pipe(distinctUntilChanged(),
            takeUntil(this.mnOnDestroy))
      .subscribe(setBucketUrlParam);

    bucketsWithParams
      .pipe(filter(([buckets, param]) => param && !buckets.includes(param)),
            pluck(0, 0),
            takeUntil(this.mnOnDestroy))
      .subscribe(setBucketUrlParam);

    bucketsWithParams
      .pipe(filter(([_, param]) => !param),
            pluck(0, 0),
            takeUntil(this.mnOnDestroy))
      .subscribe(v => setBucketUrlParam(v, "replace"));

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

    this.permissions = mnPermissions.export;
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
