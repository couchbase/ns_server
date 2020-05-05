import { Injectable } from "/ui/web_modules/@angular/core.js";
import { HttpClient } from '/ui/web_modules/@angular/common/http.js';
import { UIRouter } from "/ui/web_modules/@uirouter/angular.js";
import { MnHttpRequest } from './mn.http.request.js';

import { BehaviorSubject} from "/ui/web_modules/rxjs.js";

const restApiBase = "/pools/default/buckets";

export { MnCollectionsService }

class MnCollectionsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient,
    UIRouter
  ]}

  constructor(http, uiRouter) {
    this.http = http;
    this.stream = {};


    this.stream.updateManifest =
      new BehaviorSubject();

    this.stream.addScopeHttp =
      new MnHttpRequest(this.addScope.bind(this)).addSuccess().addError();

    this.stream.deleteScopeHttp =
      new MnHttpRequest(this.deleteScope.bind(this)).addSuccess().addError();

    this.stream.addCollectionHttp =
      new MnHttpRequest(this.addCollection.bind(this)).addSuccess().addError();

    this.stream.deleteCollectionHttp =
      new MnHttpRequest(this.deleteCollection.bind(this)).addSuccess().addError();
  }

  getManifest(bucket) {
    return this.http.get(`${restApiBase}/${bucket}/collections`);
  }

  addScope([bucket, body]) {
    return this.http.post(`${restApiBase}/${bucket}/collections`, body);
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
