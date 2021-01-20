import { NgModule } from '/ui/web_modules/@angular/core.js';
import { Injectable } from "/ui/web_modules/@angular/core.js";
import { HttpClient } from '/ui/web_modules/@angular/common/http.js';
import { UIRouter } from "/ui/web_modules/@uirouter/angular.js";
import { MnHttpRequest } from './mn.http.request.js';

import {BehaviorSubject, Subject, NEVER,
        of, merge, fromEvent} from "/ui/web_modules/rxjs.js";
import {map, shareReplay, filter, withLatestFrom, pairwise,
        switchMap, pluck, takeUntil, mapTo} from '/ui/web_modules/rxjs/operators.js';

import {MnBucketsService} from './mn.buckets.service.js';
import {MnHelperService} from './mn.helper.service.js';
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';

const restApiBase = "/pools/default/buckets";

export { MnCollectionsService, MnCollectionsServiceModule }

class MnCollectionsServiceModule {
  static get annotations() { return [
    new NgModule({
      providers: [
        MnCollectionsService,
        MnBucketsService,
        MnPermissions,
        MnHelperService
      ]
    })
  ]}
}

class MnCollectionsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient,
    UIRouter,
    MnBucketsService,
    MnPermissions,
    MnHelperService
  ]}

  constructor(http, uiRouter, mnBucketsService, mnPermissions, mnHelperService) {
    this.http = http;
    this.stream = {};

    this.mnHelperService = mnHelperService;

    this.stream.updateManifest =
      new BehaviorSubject();

    this.stream.addScopeHttp =
      new MnHttpRequest(this.addScope.bind(this))
      .addSuccess()
      .addError(map(error => {
        if (error.status === 404) {
          return {errors: {bucketName: "This bucket doesn't exist"}};
        }
        if (typeof error === "string") {
          //hanlde "Scope with this name already exists" error
          return {errors: {name: error}};
        }
        return error;
      }));

    this.stream.deleteScopeHttp =
      new MnHttpRequest(this.deleteScope.bind(this)).addSuccess().addError();

    this.stream.addCollectionHttp =
      new MnHttpRequest(this.addCollection.bind(this)).addSuccess().addError();

    this.stream.deleteCollectionHttp =
      new MnHttpRequest(this.deleteCollection.bind(this)).addSuccess().addError();

    this.stream.collectionBuckets = mnBucketsService.stream.bucketsMembaseEphemeral
      .pipe(map(buckets => buckets
                .filter(bucket => {
                  let scope = mnPermissions.export.cluster.collection[bucket.name + ':.:.'];
                  return scope && scope.collections.read;
                })),
            shareReplay({refCount: true, bufferSize: 1}));
  }

  createCollectionSelector(options) {
    var filterKey = options.isRolesMode ? "value" : "name";

    var outsideClick = fromEvent(document, 'click');

    var doFocus = new Subject();

    var filters = options.steps.reduce((acc, step) => {
      acc[step] = this.mnHelperService.createFilter(options.component, filterKey);
      return acc;
    }, {});

    var onFocus = options.steps.reduce((acc, step) => {
      acc[step] = new Subject();
      return acc;
    }, {});

    var result = new BehaviorSubject(
      options.steps.reduce((acc, step) => {
        acc[step] = null;
        return acc;
      }, {}));

    var selectionDone =
        result.pipe(filter(v => Object.values(v)
                           .filter(v => !!v).length == options.steps.length));

    var step =
        merge(merge.apply(merge,
                          options.steps.map(step => onFocus[step].pipe(filter(v => v),
                                                                       mapTo(step)))),
              selectionDone.pipe(mapTo("ok")))
        .pipe(shareReplay({refCount: true, bufferSize: 1}));


  var showHideDropdown =
      merge(outsideClick.pipe(mapTo("ok")),
            step)
      .pipe(map(v => v !== "ok"));

    var list = step
        .pipe(withLatestFrom(result),
              switchMap(options.isRolesMode ?
                        rolesPayload.bind(this) :
                        httpPayload.bind(this)),
              shareReplay({refCount: true, bufferSize: 1}));

    function disableFields(index) {
      options.steps.slice(index).forEach(step => {
        filters[step].group.get("value").disable();
      });
    }

    function setFieldsValues(index, child, value) {
      options.steps.slice(index).forEach(step => {
        value[step] = child;
        filters[step].group.get("value").setValue(child ? child.value : "");
      });
    }

    function httpPayload([step, g]) {
      let rv;
      switch (step) {
      case "bucket":
        rv = options.buckets;
        break;
      case "scope":
        rv = this.getManifest(g.bucket.name).pipe(pluck("scopes"));
        break;
      case "collection":
        rv = of(g.scope.collections);
        break;
      case "ok":
        return NEVER;
      }
      return rv.pipe(filters[step].pipe);
    }

    function rolesPayload([step, g]) {
      let rv;
      switch (step) {
      case "bucket":
        rv = of([{value: "*"},
                 ...options.buckets]);
        break;
      case "scope":
        rv = of([{value: "*"},
                 ...(g.bucket.children ? g.bucket.children[step + "_name"] : [])]);
        break;
      case "collection":
        rv = of([{value: "*"},
                 ...(g.scope.children ? g.scope.children[step + "_name"] : [])]);
        break;
      case "ok":
        return NEVER;
      }
      return rv.pipe(filters[step].pipe);
    }

    function setResultItem(item, step) {
      let value = result.getValue();
      let currentIndex = options.steps.indexOf(step);
      let currentValue = item[filterKey];
      let nextStep = options.steps[currentIndex + 1];
      if (currentValue == "*") {
        disableFields(currentIndex + 1);
        setFieldsValues(currentIndex + 1, {value: "*"}, value);
        value[step] = item;
        result.next(value);
      } else {
        disableFields(currentIndex + 1);
        setFieldsValues(currentIndex + 1, null, value);
        value[step] = item;
        result.next(value);
        if (nextStep) {
          filters[nextStep].group.get("value").enable();
          doFocus.next(nextStep);
        }
      }
    }

    function reset() {
      var next = {};
      disableFields(1);
      setFieldsValues(0, null, next);
      result.next(next);
    }

    disableFields(1);

    step
      .pipe(pairwise(),
            withLatestFrom(result),
            takeUntil(options.component.mnOnDestroy))
      .subscribe(([[prevStep, step], result]) => {
        if (prevStep && prevStep !== "ok") {
          let value = result[prevStep] && result[prevStep][filterKey];
          filters[prevStep].group.get("value").setValue(value);
        }
        if (step && step !== "ok") {
          filters[step].group.get("value").setValue("");
        }
      });

    return {
      reset,
      filters,
      filterKey,
      options,
      setResultItem,
      stream: {
        step,
        list,
        result,
        doFocus,
        onFocus,
        showHideDropdown
      }
    };
  }

  getManifest(bucket) {
    bucket = encodeURIComponent(bucket);
    return this.http.get(`${restApiBase}/${bucket}/scopes`);
  }

  addScope({name, bucketName}) {
    bucketName = encodeURIComponent(bucketName);
    return this.http.post(`${restApiBase}/${bucketName}/scopes`, {
      name: name
    });
  }

  addCollection([bucket, scope, name]) {
    bucket = encodeURIComponent(bucket);
    scope = encodeURIComponent(scope);
    return this.http.post(`${restApiBase}/${bucket}/scopes/${scope}/collections`, {name: name});
  }

  deleteScope([bucket, scope]) {
    bucket = encodeURIComponent(bucket);
    scope = encodeURIComponent(scope);
    return this.http.delete(`${restApiBase}/${bucket}/scopes/${scope}`);
  }

  deleteCollection([bucket, scope, collection]) {
    bucket = encodeURIComponent(bucket);
    scope = encodeURIComponent(scope);
    collection = encodeURIComponent(collection);
    return this.http.delete(`${restApiBase}/${bucket}/scopes/${scope}/collections/${collection}`);
  }
}
