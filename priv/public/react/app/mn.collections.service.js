/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import { HttpParams } from '@angular/common/http';
import { HttpClient } from './mn.http.client.js';
import { BehaviorSubject } from 'rxjs';
import { map, shareReplay } from 'rxjs/operators';

import { MnHttpRequest } from './mn.http.request.js';
import { MnBucketsService } from './mn.buckets.service.js';
import mnPermissions from './components/mn_permissions.js';

const restApiBase = '/pools/default/buckets';

class MnCollectionsServiceClass {
  constructor(http, mnBucketsService, mnPermissions) {
    this.http = http;
    this.stream = {};

    this.stream.updateManifest = new BehaviorSubject();

    this.stream.addScopeHttp = new MnHttpRequest(this.addScope.bind(this))
      .addSuccess()
      .addError(
        map((error) => {
          if (error.status === 404) {
            return { errors: { bucketName: "This bucket doesn't exist" } };
          }
          if (typeof error === 'string') {
            //hanlde "Scope with this name already exists" error
            return { errors: { name: error } };
          }
          return error;
        })
      );

    this.stream.deleteScopeHttp = new MnHttpRequest(this.deleteScope.bind(this))
      .addSuccess()
      .addError();

    this.stream.addCollectionHttp = new MnHttpRequest(
      this.addCollection.bind(this)
    )
      .addSuccess()
      .addError();

    this.stream.modifyCollectionHttp = new MnHttpRequest(
      this.modifyCollection.bind(this)
    )
      .addSuccess()
      .addError();

    this.stream.deleteCollectionHttp = new MnHttpRequest(
      this.deleteCollection.bind(this)
    )
      .addSuccess()
      .addError();

    this.stream.collectionBuckets =
      mnBucketsService.stream.bucketsMembaseEphemeral.pipe(
        map((buckets) =>
          buckets.filter((bucket) => {
            let scope =
              mnPermissions.export.getValue().cluster.collection[
                bucket.name + ':.:.'
              ];
            return scope && scope.collections.read;
          })
        ),
        shareReplay({ refCount: true, bufferSize: 1 })
      );
  }

  extractInterestingStatsPipe(statsStream) {
    return statsStream.pipe(
      map((stats) =>
        Object.keys(stats).reduce((acc, statName) => {
          if (stats[statName] && stats[statName]['aggregate']) {
            acc[statName] = stats[statName]['aggregate'].values
              .slice()
              .reverse()
              .find((stat) => stat != null)[1];
          }
          return acc;
        }, {})
      ),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
  }

  getManifest(bucket) {
    bucket = encodeURIComponent(bucket);
    return this.http.get(`${restApiBase}/${bucket}/scopes`);
  }

  addScope({ name, bucketName }) {
    bucketName = encodeURIComponent(bucketName);
    return this.http.post(`${restApiBase}/${bucketName}/scopes`, {
      name: name,
    });
  }

  addCollection([bucket, scope, name, ttl]) {
    bucket = encodeURIComponent(bucket);
    scope = encodeURIComponent(scope);
    const payload = { name: name };
    if (ttl !== '' && ttl !== undefined) {
      // MB-58183 - maxTTL should be unset if the user specifies blank ('')
      // MB-59982 - maxTTL should be unset for CE (undefined)
      payload.maxTTL = ttl;
    }
    return this.http.post(
      `${restApiBase}/${bucket}/scopes/${scope}/collections`,
      payload
    );
  }

  modifyCollection([bucket, scope, name, ttl]) {
    bucket = encodeURIComponent(bucket);
    scope = encodeURIComponent(scope);
    name = encodeURIComponent(name);
    // unspecified TTL must be sent as '-1'
    if (ttl === '') {
      ttl = -1;
    }
    // must be URL-encoded, so use HttpParams
    const httpParams = new HttpParams().append('maxTTL', ttl);
    return this.http.patch(
      `${restApiBase}/${bucket}/scopes/${scope}/collections/${name}`,
      httpParams
    );
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
    return this.http.delete(
      `${restApiBase}/${bucket}/scopes/${scope}/collections/${collection}`
    );
  }
}

const MnCollectionsService = new MnCollectionsServiceClass(
  HttpClient,
  MnBucketsService,
  mnPermissions
);
export { MnCollectionsService };
