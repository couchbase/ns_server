import { Injectable } from "/ui/web_modules/@angular/core.js";
import { HttpClient } from '/ui/web_modules/@angular/common/http.js';
import { map } from '/ui/web_modules/rxjs/operators.js';
import { MnHttpRequest } from './mn.http.request.js';

export { MnStatsService };

class MnStatsService {
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

  postStatsRange(configs) {
    return this.http.post("/pools/default/stats/range/", configs)
      .pipe(map(resp => JSON.parse(resp)));
  }
}
