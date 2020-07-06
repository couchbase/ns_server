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

    this.stream.collectionBuckets = mnBucketsService.stream.getBucketsByName
      .pipe(map(buckets => Object
                .keys(buckets)
                .filter(bucketName =>
                        mnPermissions.export.cluster.bucket[bucketName] &&
                        mnPermissions.export.cluster.bucket[bucketName].collections.read)),
            shareReplay({refCount: true, bufferSize: 1}));
  }

  getManifest(bucket) {
    return this.http.get(`${restApiBase}/${bucket}/collections`);
  }

  addScope(values) {
    return this.http.post(`${restApiBase}/${values.bucketName}/collections`, {
      name: values.name
    });
  }

  addCollection([bucket, {scope, name}]) {
    return this.http.post(`${restApiBase}/${bucket}/collections/${scope}`, {name: name});
  }

  deleteScope([bucket, scope]) {
    return this.http.delete(`${restApiBase}/${bucket}/collections/${scope}`);
  }

  deleteCollection([bucket, scope, collection]) {
    return this.http.delete(`${restApiBase}/${bucket}/collections/${scope}/${collection}`);
  }
}
