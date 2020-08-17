import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {FormBuilder} from "/ui/web_modules/@angular/forms.js";
import {UIRouter} from "/ui/web_modules/@uirouter/angular.js";
import {pluck, filter, switchMap, distinctUntilChanged, withLatestFrom,
        shareReplay, takeUntil, tap, map} from '/ui/web_modules/rxjs/operators.js';
import {combineLatest, Subject, timer} from "/ui/web_modules/rxjs.js";
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js";
import {MnPermissions, MnServersService} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';
import {MnCollectionsAddScopeComponent} from './mn.collections.add.scope.component.js';
import {MnCollectionsAddItemComponent} from './mn.collections.add.item.component.js';

import {MnHelperService} from './mn.helper.service.js';

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
    MnHelperService,
    MnServersService
  ]}

  constructor(mnCollectionsService, mnPermissions,
              uiRouter, modalService, formBuilder, mnHelperService, mnServersService) {
    super();

    var clickAddScope = new Subject();
    var clickAddCollection = new Subject();

    var bucketSelect = formBuilder.group({item: null});

    var setBucket = (v) =>
        bucketSelect.patchValue({item: v});

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
        ).pipe(filter(([param, buckets]) => param && buckets
                      .map(bucket => bucket.name).includes(param)),
               pluck(1, 0),
               distinctUntilChanged(),
               shareReplay({refCount: true, bufferSize: 1}));

    var bucketsWithParams =
        getBuckets.pipe(withLatestFrom(getBucketUrlParam));

    var statusClass = getBucketUrlParamDefined
        .pipe(map(item =>
                  ("dynamic_" + mnServersService.addNodesByStatus(item.nodes).statusClass)),
              takeUntil(this.mnOnDestroy),
              distinctUntilChanged());

    getBucketUrlParamDefined
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(setBucket);

    bucketSelect.get("item").valueChanges
      .pipe(pluck("name"),
            distinctUntilChanged(),
            takeUntil(this.mnOnDestroy))
      .subscribe(setBucketUrlParam);

    bucketsWithParams
      .pipe(filter(([buckets, param]) => param && !buckets
                   .map(bucket => bucket.name).includes(param)),
            pluck(0, 0, "name"),
            takeUntil(this.mnOnDestroy))
      .subscribe(setBucketUrlParam);

    bucketsWithParams
      .pipe(filter(([_, param]) => !param),
            pluck(0, 0, "name"),
            takeUntil(this.mnOnDestroy))
      .subscribe(v => setBucketUrlParam(v, "replace"));

    var scopesSorter = mnHelperService.createSorter("name");
    var scopesFilter = mnHelperService.createFilter("name");

    var scopes =
        combineLatest(getBucketUrlParamDefined,
                      mnCollectionsService.stream.updateManifest,
                      timer(0, 5000))
        .pipe(switchMap(([bucket]) => mnCollectionsService.getManifest(bucket.name)),
              pluck("scopes"),
              scopesSorter.pipe,
              scopesFilter.pipe,
              shareReplay({refCount: true, bufferSize: 1}));

    var scopesPaginator = mnHelperService.createPagenator(this, scopes, "scopesPage");


    clickAddScope
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => {
        var ref = modalService.open(MnCollectionsAddScopeComponent);
        ref.componentInstance.bucketName = bucketSelect.get("item").value.name;
      });

    clickAddCollection
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => {
        var ref = modalService.open(MnCollectionsAddItemComponent);
        ref.componentInstance.bucketName = bucketSelect.get("item").value.name;
      });

    this.scopesSorter = scopesSorter;
    this.scopesFilter = scopesFilter;
    this.scopesPaginator = scopesPaginator;

    this.permissions = mnPermissions.export;
    this.buckets = getBuckets;
    this.bucketSelect = bucketSelect;
    this.scopes = scopes;
    this.clickAddScope = clickAddScope;
    this.clickAddCollection = clickAddCollection;
    this.statusClass = statusClass;
  }

  trackByFn(_, scope) {
    return scope.name;
  }
}
