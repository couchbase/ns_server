import {Injectable} from '/ui/web_modules/@angular/core.js';
import {BehaviorSubject, combineLatest, zip} from '/ui/web_modules/rxjs.js';
import {scan, map, shareReplay, distinctUntilChanged,
        debounceTime, startWith, pluck, takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {not, sort, prop, descend, ascend, equals} from '/ui/web_modules/ramda.js';
import {FormBuilder} from "/ui/web_modules/@angular/forms.js";
import {UIRouter} from "/ui/web_modules/@uirouter/angular.js";

export {MnHelperService};

class MnHelperService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    FormBuilder,
    UIRouter
  ]}

  constructor(formBuilder, uiRouter) {
    this.formBuilder = formBuilder;
    this.uiRouter = uiRouter;
  }

  get daysOfWeek() {
    return ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday']
  }

  get IEC() {
    return {Ki: 1024, Mi: 1024 * 1024, Gi: 1024 * 1024 * 1024}
  }

  invert(v) { //TODO: sould be replaced with Ramda.not
    return !v;
  }

  isJson(str) {
    try {
      JSON.parse(str);
    } catch (e) {
      return false;
    }
    return true;
  }

  calculateMaxMemorySize(totalRAMMegs) {
    return Math.floor(Math.max(totalRAMMegs * 0.8, totalRAMMegs - 1024));
  }

  pluckMemoryQuotas(source) {
    return source[1].reduce((acc, service) => {
      acc[service] = source[0][this.getServiceQuotaName(service)];
      return acc;
    }, {});
  }

  getServiceQuotaName(service) {
    switch (service) {
    case "kv": return "memoryQuota";
    default: return service + "MemoryQuota";
    }
  }

  getServiceVisibleName(service) {
    switch (service) {
    case "kv": return "Data";
    case "index": return "Index";
    case "fts": return "Search";
    case "n1ql": return "Query";
    case "eventing": return "Eventing";
    case "cbas": return "Analytics";
    case "backup": return "Backup";
    }
  }

  validateEqual(key1, key2, erroName) {
    return function (group) {
      if (group.get(key1).value !== group.get(key2).value) {
        var rv = {};
        rv[erroName] = true;
        return rv;
      }
    }
  }

  createToggle(defaultValue) {
    var click = new BehaviorSubject(defaultValue);
    return {
      click: click,
      state: click.pipe(scan(not, true),
                        shareReplay({refCount: true, bufferSize: 1}))
    };
  }

  createSorter(defaultValue) {
    var toggler = this.createToggle(defaultValue);
    var click = toggler.click.pipe(distinctUntilChanged());
    return {
      click: click,
      state: toggler.state,
      pipe: (arrayStream) => {
        return combineLatest(arrayStream, zip(toggler.click, toggler.state))
          .pipe(map(([array, [sortByValue, isDesc]]) => {
            var ascOrDesc = isDesc ? descend : ascend;
            return sort(ascOrDesc(prop(sortByValue)), array);
          }), shareReplay({refCount: true, bufferSize: 1}));
      }
    };
  }

  createFilter() {
    var group = this.formBuilder.group({value: ""});
    var inputStream =
        group.get("value").valueChanges.pipe(debounceTime(200),
                                             startWith(""));

    var filterFunction = ([list, filterValue]) =>
        list ? list.filter(item => item.name.includes(filterValue)) : [];

    // R.filter(R.compose(R.any(R.contains(val)), R.values))

    return {
      group: group,
      pipe: (arrayStream) => {
        return combineLatest(arrayStream, inputStream)
          .pipe(map(filterFunction),
                shareReplay({refCount: true, bufferSize: 1}));
      }
    };
  }

  createPagenator(component, arrayStream, stateParam) {
    var params = {};
    var urlParam =
        this.uiRouter.globals.params$.pipe(pluck(stateParam));

    var group = this.formBuilder.group({size: null, page: null});

    var setParamToGroup = (scopesPage) => {
      Object.assign(params, scopesPage)
      group.patchValue(scopesPage);
    };

    var setParamToUrl = (scopesPage, location) => {
      console.log(scopesPage)
      var params = {};
      scopesPage = scopesPage ? Object.assign({}, group.value, scopesPage) : null;
      params[stateParam] = scopesPage;
      this.uiRouter.stateService.go('.', params, {
        notify: false,
        location: location || true
      });
    };

    group.valueChanges
      .pipe(distinctUntilChanged(),
            takeUntil(component.mnOnDestroy))
      .subscribe(setParamToUrl);

    urlParam
      .pipe(takeUntil(component.mnOnDestroy))
      .subscribe(setParamToGroup);

    var page = combineLatest(arrayStream, urlParam)
        .pipe(map(([array, {size, page}]) => {
          return array.slice((page-1) * size, (page-1) * size + size)}),
              shareReplay({refCount: true, bufferSize: 1}));

    return {
      group: group,
      params: params,
      page: page,
      setParamToUrl: setParamToUrl
    };
  }
}
// var mn = mn || {};
// mn.helper = mn.helper || {};
// mn.helper.createBucketTypePipe = (function () {
//   "use strict";

//   return function (bucketType) {
//     var capitalize = bucketType.charAt(0).toUpperCase() + bucketType.slice(1);

//     MnBucketType.annotations = [
//       new ng.core.Pipe({
//         name: "mnIs" + capitalize
//       })
//     ];

//     MnBucketType.prototype.transform = transform;

//     return MnBucketType;

//     function MnBucketType() {
//     }

//     function transform(bucket) {
//       if (bucket instanceof ng.forms.FormGroup) {
//         return bucket.get("bucketType").value === bucketType;
//       } else if (bucket instanceof Object) {
//         return bucket.bucketType === bucketType;
//       } else {
//         return bucket === bucketType;
//       }
//     }

//   }
  // })();
  // mn.pipes.MnIsMembase = mn.helper.createBucketTypePipe("membase")
// mn.pipes.MnIsEphemeral = mn.helper.createBucketTypePipe("ephemeral");
// mn.pipes.MnIsMemcached = mn.helper.createBucketTypePipe("memcached");
