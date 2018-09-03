var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.extends = (function () {

  var extendStatics = Object.setPrototypeOf ||
      ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
      function (d, b) { for (var p in b) if (b.hasOwnProperty(p)) d[p] = b[p]; };

  function __extends(d, b) {
    extendStatics(d, b);
    function __() { this.constructor = d; }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  }

  return __extends;
})();

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.validateEqual = (function () {
  return function (key1, key2, erroName) {
    return function (group) {
      if (group.get(key1).value !== group.get(key2).value) {
        var rv = {};
        rv[erroName] = true;
        return rv;
      }
    }
  }
})();

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.daysOfWeek = (function () {
  return [
    'Monday',
    'Tuesday',
    'Wednesday',
    'Thursday',
    'Friday',
    'Saturday',
    'Sunday'
  ];
})();

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.IEC = (function () {
  return {
    Ki: 1024,
    Mi: 1024 * 1024,
    Gi: 1024 * 1024 * 1024
  };
})();

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.calculateMaxMemorySize = (function () {
  return function (totalRAMMegs) {
    return Math.floor(Math.max(totalRAMMegs * 0.8, totalRAMMegs - 1024));
  }
})();

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.createReplaySubject = (function (Rx) {
  return function () {
    return new Rx.ReplaySubject(1);
  }
})(window.rxjs);

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.invert = (function () {
  return function (v) {
    return !v;
  }
})();

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.createBucketTypePipe = (function () {
  "use strict";

  return function (bucketType) {
    var capitalize = bucketType.charAt(0).toUpperCase() + bucketType.slice(1);

    MnBucketType.annotations = [
      new ng.core.Pipe({
        name: "mnIs" + capitalize
      })
    ];

    MnBucketType.prototype.transform = transform;

    return MnBucketType;

    function MnBucketType() {
    }

    function transform(bucket) {
      if (bucket instanceof ng.forms.FormGroup) {
        return bucket.get("bucketType").value === bucketType;
      } else if (bucket instanceof Object) {
        return bucket.bucketType === bucketType;
      } else {
        return bucket === bucketType;
      }
    }

  }
})();



var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.DetailsHashObserver = (function (Rx) {

  DetailsHashObserver.prototype.isOpened = isOpened;
  DetailsHashObserver.prototype.getNewHashValue = getNewHashValue;
  DetailsHashObserver.prototype.prepareHashValue = prepareHashValue;
  DetailsHashObserver.prototype.setNewHashValue = setNewHashValue;

  return DetailsHashObserver;

  function DetailsHashObserver(uiRouter, stateName, hashKey, mnOnDestroy, initialValueStream) {
    this.uiRouter = uiRouter;
    this.hashKey = hashKey;
    this.stateName = stateName;
    this.mnOnDestroy = mnOnDestroy;

    this.stream = {};
    this.stream.toggleDetails = new Rx.Subject();

    this.stream.openedDetailsHash =
      this.uiRouter.globals.params$.pipe(
        Rx.operators.pluck(this.hashKey),
        Rx.operators.distinctUntilChanged(),
        Rx.operators.map(this.prepareHashValue.bind(this))
      );

    this.stream.isOpened =
      Rx.combineLatest(
        Rx.merge(
          initialValueStream
            .pipe(Rx.operators.distinctUntilChanged()),
          this.stream.toggleDetails
        ),
        this.stream.openedDetailsHash
      )
      .pipe(Rx.operators.map(this.isOpened.bind(this)));

    this.stream.newHashValue =
      this.stream.toggleDetails.pipe(
        Rx.operators.withLatestFrom(this.stream.openedDetailsHash),
        Rx.operators.map(this.getNewHashValue.bind(this))
      );

    this.stream.newHashValue
      .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
      .subscribe(this.setNewHashValue.bind(this));
  }

  function setNewHashValue(newHashValue) {
    var stateParams = {};
    stateParams[this.hashKey] = newHashValue;
    this.uiRouter.stateService.go(this.stateName, stateParams);
  }

  function prepareHashValue(v) {
    return (v || []).map(decodeURIComponent);
  }

  function getNewHashValue(values) {
    values[1] = _.clone(values[1]);
    if (this.isOpened(values)) {
      return _.difference(values[1], [String(values[0])])
    } else {
      values[1].push(values[0]);
      return values[1];
    }
  }

  function isOpened(values) {
    return values[1].indexOf(values[0]) > -1;
  }

})(window.rxjs);

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.errorToStream = (function (Rx) {
  return function (err) {
    return Rx.of(err);
  }
})(window.rxjs);

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.isJson = (function () {
  return function (str) {
    try {
      JSON.parse(str);
    } catch (e) {
      return false;
    }
    return true;
  }
})();

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.sortByStream = (function (Rx) {
  return function (sortByStream) {
    return function (arrayStream) {
      var isAsc = sortByStream.pipe(Rx.operators.scan(mn.helper.invert, false));

      return Rx.combineLatest(
        arrayStream,
        Rx.zip(
          sortByStream,
          isAsc
        )
      ).pipe(
        Rx.operators.map(doSort),
        Rx.operators.multicast(mn.helper.createReplaySubject),
        Rx.operators.refCount()
      );

      function doSort(values) {
        var copyArray = values[0].slice();
        var sortBy = values[1][0];
        var isAsc = values[1][1];
        copyArray = _.sortBy(copyArray, sortBy);

        if (!isAsc) {
          return copyArray.reverse();
        } else {
          return copyArray;
        }
      }
    }
  }
})(window.rxjs);

mn.helper.MnPostGroupHttp = (function (Rx) {

  MnPostGroupHttp.prototype.post = post;
  MnPostGroupHttp.prototype.addSuccess = addSuccess;
  MnPostGroupHttp.prototype.addLoading = addLoading;
  MnPostGroupHttp.prototype.clearErrors = clearErrors;
  MnPostGroupHttp.prototype.getHttpGroupStreams = getHttpGroupStreams;

  return MnPostGroupHttp;

  function MnPostGroupHttp(httpMap) {
    this.request = new Rx.Subject();
    this.httpMap = httpMap;
  }

  function clearErrors() {
    _.forEach(this.httpMap, function (value, key) {
      value.clearError();
    });
  }

  function addSuccess() {
    this.success =
      Rx.zip.apply(null, this.getHttpGroupStreams("response"))
      .pipe(
        Rx.operators.filter(function (responses) {
          return !_.find(responses, function (resp) {
            return resp instanceof ng.common.http.HttpErrorResponse;
          });
        })
      );
    return this;
  }

  function post(data) {
    this.request.next();
    _.forEach(this.httpMap, function (value, key) {
      value.post(data[key]);
    });
  }

  function getHttpGroupStreams(stream) {
    return _.reduce(this.httpMap, function (result, value, key) {
      result.push(value[stream]);
      return result;
    }, []);
  }

  function addLoading() {
    this.loading =
      Rx.merge(
        Rx.zip.apply(null, this.getHttpGroupStreams("response")).pipe(
          Rx.operators.mapTo(false)
        ),
        this.request.pipe(
          Rx.operators.mapTo(true)
        )
      );
    return this;
  }

})(window.rxjs);

mn.helper.MnPostHttp = (function (Rx) {

  MnPostHttp.prototype.addResponse = addResponse;
  MnPostHttp.prototype.addSuccess = addSuccess;
  MnPostHttp.prototype.addLoading = addLoading;
  MnPostHttp.prototype.addError = addError;
  MnPostHttp.prototype.post = post;
  MnPostHttp.prototype.clearError = clearError;

  return MnPostHttp;

  function MnPostHttp(call) {
    this._dataSubject = new Rx.Subject();
    this._errorSubject = new Rx.Subject();
    this._loadingSubject = new Rx.Subject();
    this.addResponse(call);
  }

  function clearError() {
    this._errorSubject.next(null);
  }

  function addResponse(call) {
    this.response =
      this._dataSubject.pipe(
        Rx.operators.switchMap(function (data) {
          return call(data).pipe(Rx.operators.catchError(mn.helper.errorToStream));
        }),
        Rx.operators.multicast(mn.helper.createReplaySubject),
        Rx.operators.refCount()
      );
    return this;
  }

  function addError(modify) {
    var error =
        Rx.merge(
          this.response.pipe(
            Rx.operators.switchMap(function (rv) {
              if (rv instanceof ng.common.http.HttpErrorResponse) {
                return Rx.of(rv);
              } else if (mn.helper.isJson(rv)) {
                return Rx.of(new ng.common.http.HttpErrorResponse({error: rv}));
              } else {
                return Rx.NEVER;
              }
            }),
            Rx.operators.pluck("error"),
            Rx.operators.map(JSON.parse),
            Rx.operators.share()
          ),
          this._errorSubject
        );
    if (modify) {
      error = error.pipe(modify);
    }
    this.error = error;
    return this;
  }

  function addLoading() {
    this.loading =
      Rx.merge(
        this._loadingSubject,
        this.response.pipe(Rx.operators.mapTo(false))
      );

    return this;
  }

  function addSuccess(modify) {
    var success =
        this.response.pipe(
          Rx.operators.filter(function (rv) {
            return !(rv instanceof ng.common.http.HttpErrorResponse);
          }),
          Rx.operators.share()
        );
    if (modify) {
      success = success.pipe(modify);
    }
    this.success = success;
    return this;
  }

  function post(data) {
    this._loadingSubject.next(true);
    this._dataSubject.next(data);
  }
})(window.rxjs);

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.MnEventableComponent = (function (Rx) {

  var componentLifecycleHooks = [
    "OnChanges",
    "OnInit",
    "DoCheck",
    "AfterContentInit",
    "AfterContentChecked",
    "AfterViewInit",
    "AfterViewChecked",
    "OnDestroy"
  ];

  componentLifecycleHooks.forEach(function (name) {
    if (name === "OnDestroy") {
      MnDestroyableComponent.prototype["ng" + name] = function (value) {
        this["mn" + name].next();
        this["mn" + name].complete(value);
      }
    } else {
      MnDestroyableComponent.prototype["ng" + name] = function (value) {
        this["mn" + name].next(value);
      }
    }
  });

  return MnDestroyableComponent;

  function MnDestroyableComponent() {
    componentLifecycleHooks.forEach(createSubjects.bind(this));
  }

  function createSubjects(name) {
    //OnChanges triggers before OnInit, so we should keep current value
    this["mn" + name] = (name === "OnChanges") ? new Rx.BehaviorSubject() : new Rx.Subject();
  }

})(window.rxjs);

var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.jQueryLikeParamSerializer = (function () {

  jQueryParam.prototype.serializeValue = serializeValue;
  jQueryParam.prototype.serialize = serialize;
  jQueryParam.prototype.toString = toString;

  return jQueryParam;

  //function is borrowed from the Angular source code because we want to
  //use $httpParamSerializerJQLik but with properly encoded params via
  //encodeURIComponent since it uses correct application/x-www-form-urlencoded
  //encoding algorithm, in accordance with
  //https://www.w3.org/TR/html5/forms.html#url-encoded-form-data.
  //And HttpParams doesn't accept array e.g my_key=value1&my_key=value2
  //https://github.com/angular/angular/issues/19071
  function jQueryParam(params) {
    if (!params) {
      return this;
    }
    this.parts = [];
    this.serialize(params, '', true);
  }

  function toString() {
    return this.parts.join("&");
  }

  function serialize(toSerialize, prefix, topLevel) {
    if (_.isArray(toSerialize)) {
      _.forEach(toSerialize, (function (value, index) {
        this.serialize(value, prefix + (_.isObject(value) ? '[' + index + ']' : ''));
      }).bind(this));
    } else if (_.isObject(toSerialize) && !_.isDate(toSerialize)) {
      _.forEach(toSerialize, (function (value, key) {
        this.serialize(value, prefix +
                       (topLevel ? '' : '[') +
                       key +
                       (topLevel ? '' : ']'));
      }).bind(this));
    } else {
      this.parts.push(encodeURIComponent(prefix) + '=' + encodeURIComponent(this.serializeValue(toSerialize)));
    }
  }

  function serializeValue(v) {
    if (_.isObject(v)) {
      return _.isDate(v) ? v.toISOString() : JSON.stringify(v);
    }
    if (v === null || _.isUndefined(v)) {
      return "";
    }
    return v;
  }

})();


var mn = mn || {};
mn.helper = mn.helper || {};
mn.helper.MnHttpEncoder = (function (_super) {
  "use strict";

  mn.helper.extends(MnHttpEncoder ,_super);

  MnHttpEncoder.prototype.encodeKey = encodeKey;
  MnHttpEncoder.prototype.encodeValue = encodeValue;
  MnHttpEncoder.prototype.serializeValue = serializeValue;

  return MnHttpEncoder;

  function MnHttpEncoder() {
    var _this = _super.call(this) || this;
    return _this;
  }

  function encodeKey(k) {
    return encodeURIComponent(k);
  }

  function encodeValue(v) {
    return encodeURIComponent(this.serializeValue(v));
  }

  function serializeValue(v) {
    if (_.isObject(v)) {
      return _.isDate(v) ? v.toISOString() : JSON.stringify(v);
    }
    if (v === null || _.isUndefined(v)) {
      return "";
    }
    return v;
  }
})(ng.common.http.HttpUrlEncodingCodec);
