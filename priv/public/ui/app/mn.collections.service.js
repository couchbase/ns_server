import { Injectable } from "/ui/web_modules/@angular/core.js";
import { HttpClient } from '/ui/web_modules/@angular/common/http.js';
import { UIRouter } from "/ui/web_modules/@uirouter/angular.js";
import { MnHttpRequest } from './mn.http.request.js';

import { BehaviorSubject} from "/ui/web_modules/rxjs.js";
import {map, shareReplay} from '/ui/web_modules/rxjs/operators.js';

import {MnBucketsService} from './mn.buckets.service.js';
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';

const restApiBase = "/pools/default/buckets";

export { MnCollectionsService }

class MnCollectionsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient,
    UIRouter,
    MnBucketsService,
    MnPermissions
  ]}

  constructor(http, uiRouter, mnBucketsService, mnPermissions) {
    this.http = http;
    this.stream = {};


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

    this.stream.collectionBuckets = mnBucketsService.stream.getBuckets
      .pipe(map(buckets => buckets
                .filter(bucket => {
                  let scope = mnPermissions.export.cluster.collection[bucket.name + ':.:.'];
                  return scope && scope.collections.read;
                })),
            shareReplay({refCount: true, bufferSize: 1}));
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
