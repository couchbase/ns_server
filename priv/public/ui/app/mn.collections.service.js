import { NgModule } from '/ui/web_modules/@angular/core.js';
import { Injectable } from "/ui/web_modules/@angular/core.js";
import { HttpClient } from '/ui/web_modules/@angular/common/http.js';
import { UIRouter } from "/ui/web_modules/@uirouter/angular.js";
import { MnHttpRequest } from './mn.http.request.js';

import {BehaviorSubject, Subject, NEVER,
        of, merge, fromEvent} from "/ui/web_modules/rxjs.js";
import {map, shareReplay, filter, withLatestFrom, pairwise, catchError,
        switchMap, pluck, takeUntil, mapTo, take, distinctUntilChanged} from '/ui/web_modules/rxjs/operators.js';

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

    this.mnBucketsService = mnBucketsService

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
    var setValueConfig = {emitEvent: false};

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

    var setStepsValuesToFields = () => {
      let value = result.getValue();
      Object.keys(value).forEach(key => {
        if (value[key]) {
          filters[key].group.get("value").setValue(
            value[key] ? value[key][filterKey] : "", setValueConfig);
        }
      });
    };

    var mapFocusToStep =
        merge.apply(merge,
                    options.steps.map(step => onFocus[step].pipe(filter(v => v),
                                                                 mapTo(step))));
    var step =
        merge(mapFocusToStep,
              selectionDone.pipe(mapTo("ok")))
        .pipe(shareReplay({refCount: true, bufferSize: 1}));

    outsideClick
      .pipe(takeUntil(options.component.mnOnDestroy))
      .subscribe(setStepsValuesToFields);

    var showHideDropdown =
        merge(outsideClick.pipe(mapTo("ok")),
              step)
        .pipe(map(v => v !== "ok"));

    var list = step
        .pipe(distinctUntilChanged(),
              withLatestFrom(result),
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

    function getStepList([step, g]) {
      switch (step) {
      case "bucket":
        return options.buckets || this.stream.collectionBuckets;
      case "scope":
        return g.bucket ?
          this.getManifest(g.bucket.name).pipe(pluck("scopes"),
                                               catchError(() => of([]))) :
          of([]);
      case "collection":
        return of(g.scope.collections);
      case "ok":
        return NEVER;
      }
    }

    function httpPayload([step, g]) {
      let rv = getStepList.bind(this)([step, g]);

      if (step !== "ok") {
        return rv.pipe(filters[step].pipe);
      } else {
        return rv;
      }
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

    function setKeyspace(setVals, useDefault) {
      let next = {};

      function setDefault(key, list) {
        next[key] =  list.find(item => item[filterKey] == setVals[key]) || {name: setVals[key]}
      }

      getStepList
        .bind(this)(["bucket"])
        .pipe(take(1),
              switchMap(list => {
                setDefault("bucket", list);
                return getStepList.bind(this)(["scope", next]).pipe(take(1));
              }))
        .subscribe(list => {
          setDefault("scope", list);
          result.next(next);
          setStepsValuesToFields();
          filters["scope"].group.get("value").enable();
        });

    }


    disableFields(1);

    step
      .pipe(pairwise(),
            withLatestFrom(result),
            takeUntil(options.component.mnOnDestroy))
      .subscribe(([[prevStep, step], result]) => {
        if (prevStep && prevStep !== "ok") {
          let value = result[prevStep] && result[prevStep][filterKey];
          filters[prevStep].group.get("value").setValue(value, setValueConfig);
        }
        if (step && step !== "ok") {
          filters[step].group.get("value").setValue("", setValueConfig);
        }
      });

    if (options.defaults) {
      setKeyspace.bind(this)(options.defaults, true);
    }

    return {
      setKeyspace: setKeyspace.bind(this),
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
