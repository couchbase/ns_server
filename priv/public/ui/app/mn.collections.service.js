import { Injectable } from "/ui/web_modules/@angular/core.js";
import { HttpClient } from '/ui/web_modules/@angular/common/http.js';
import { MnHttpRequest } from './mn.http.request.js';

const restApiBase = "/pools/default/buckets";

export { MnCollectionsService }

class MnCollectionsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient
  ]}

  constructor(http) {
    this.http = http;
    this.stream = {};
  }

  getManifest(bucket) {
    return this.http.get(`${restApiBase}/${bucket}/collections`);
  }

  addScope(bucket, body) {
    return this.http.post(`${restApiBase}/${bucket}/collections`, body);
  }

  addCollection(bucket, scope, body) {
    return this.http.post(`${restApiBase}/${bucket}/collections/${scope}`, body);
  }

  deleteScope(bucket, scope) {
    return this.http.delete(`${restApiBase}/${bucket}/collections/${scope}`);
  }

  deleteCollection(bucket, scope, collection) {
    return this.http.delete(`${restApiBase}/${bucket}/collections/${scope}/${collection}`);
  }
}
