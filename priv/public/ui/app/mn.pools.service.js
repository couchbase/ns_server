import { Injectable } from '../web_modules/@angular/core.js';
import { HttpClient, HttpErrorResponse } from '../web_modules/@angular/common/http.js';
import { BehaviorSubject } from '../web_modules/rxjs.js';
import { switchMap,
         shareReplay,
         pluck,
         distinctUntilChanged,
         map,
         tap
       } from '../web_modules/rxjs/operators.js';
import { MnParseVersion } from './mn.pipes.js'

export { MnPoolsService };

let launchID =  (new Date()).valueOf() + '-' + ((Math.random() * 65536) >> 0);

class MnPoolsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient,
    MnParseVersion
  ]}

  constructor(http, mnParseVersionPipe) {
    this.http = http;
    this.stream = {};

    this.stream.getSuccess =
      (new BehaviorSubject()).pipe(switchMap(this.get.bind(this)),
                                   shareReplay({refCount: true, bufferSize: 1}));

    this.stream.isEnterprise =
      this.stream.getSuccess.pipe(pluck("isEnterprise"), distinctUntilChanged());

    this.stream.implementationVersion =
      this.stream.getSuccess.pipe(pluck("implementationVersion"));

    this.stream.majorMinorVersion =
      this.stream.implementationVersion.pipe(
        map(mnParseVersionPipe.transform.bind(mnParseVersionPipe)),
        map(function (rv) {
          return rv[0].split('.').splice(0,2).join('.');
        })
      );

    this.stream.mnServices =
      this.stream.isEnterprise
      .pipe(map(function (isEnterprise) {
        return isEnterprise ?
          ["kv", "n1ql", "index", "fts", "cbas", "eventing", "backup"] :
          ["kv", "index", "fts", "n1ql"];
      }), shareReplay({refCount: true, bufferSize: 1}));

    this.stream.quotaServices =
      this.stream.isEnterprise
      .pipe(map(function (isEnterprise) {
        return isEnterprise ?
          ["kv", "index", "fts", "cbas", "eventing"] :
          ["kv", "index", "fts"];
      }), shareReplay({refCount: true, bufferSize: 1}));
  }

  get() {
    return this.http.get('/pools').pipe(
      map(function (pools) {
        pools.isInitialized = !!pools.pools.length;
        pools.launchID = pools.uuid + '-' + launchID;
        return pools;
      })
    );
  }
}
