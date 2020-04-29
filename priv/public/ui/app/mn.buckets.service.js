import {Injectable} from "/ui/web_modules/@angular/core.js";
import {pluck,
        switchMap,
        shareReplay,
        distinctUntilChanged} from "/ui/web_modules/rxjs/operators.js";
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
    this.stream.buckets =
      bucketsUri.pipe(switchMap(this.get.bind(this)),
                      shareReplay({refCount: true, bufferSize: 1}));
  }

  get(url) {
    return this.http.get(url, {params: new HttpParams().set("skipMap", true)});
  }
}
