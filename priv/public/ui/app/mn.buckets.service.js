import {Injectable} from "/ui/web_modules/@angular/core.js";
import {pluck,
        switchMap,
        shareReplay,
        distinctUntilChanged,
        map} from "/ui/web_modules/rxjs/operators.js";
import {HttpClient, HttpParams} from '/ui/web_modules/@angular/common/http.js';
import {MnAdminService} from './mn.admin.service.js';

export {MnBucketsService};

class MnBucketsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient,
    MnAdminService
  ]}

  constructor(http, mnAdminService) {
    this.stream = {};
    this.http = http;

    var bucketsUri =
        mnAdminService.stream.getPoolsDefault.pipe(pluck("buckets", "uri"),
                                                   distinctUntilChanged());
    this.stream.getBuckets =
      bucketsUri.pipe(switchMap(this.get.bind(this)),
                      shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getBucketsByName =
      this.stream.getBuckets.pipe(map(buckets =>
                                      buckets.reduce((acc, bucket) => {
                                        acc[bucket.name] = bucket;
                                        return acc;
                                      }, {})));
  }

  get(url) {
    return this.http.get(url, {params: new HttpParams().set("skipMap", true)});
  }
}
