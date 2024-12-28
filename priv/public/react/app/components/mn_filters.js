
import _ from 'lodash';

const jQueryLikeParamSerializerFilter = (function () {
  const parts = [];

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
      return "";
    }
    serialize(params, '', true).join("&");
  }

  function serialize(toSerialize, prefix, topLevel) {
    if (_.isArray(toSerialize)) {
      _.forEach(toSerialize, (function (value, index) {
        serialize(value, prefix + (_.isObject(value) ? '[' + index + ']' : ''));
      }).bind(this));
    } else if (_.isObject(toSerialize) && !_.isDate(toSerialize)) {
      _.forEach(toSerialize, (function (value, key) {
        serialize(value, prefix +
                       (topLevel ? '' : '[') +
                       key +
                       (topLevel ? '' : ']'));
      }).bind(this));
    } else {
      parts.push(encodeURIComponent(prefix) + '=' + encodeURIComponent(serializeValue(toSerialize)));
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


function mnFormatStorageMode(value, isEnterprise) {
  switch (value) {
  case "plasma": return "Standard GSI";
  case "forestdb": return (isEnterprise ? "Legacy" : "Standard") + " GSI";
  case "memory_optimized": return "Memory Optimized GSI";
  default: return value;
  }
}

function mnTruncateTo3Digits() {
  return function (value, leastScale, roundMethod) {
    if (!value) {
      return 0;
    }
    var scale = _.detect([100, 10, 1, 0.1, 0.01, 0.001], function (v) {return value >= v;}) || 0.0001;
    if (leastScale != undefined && leastScale > scale) {
      scale = leastScale;
    }
    scale = 100 / scale;
    return Math[roundMethod || "round"](value*scale)/scale;
  };
}

function mnPrepareQuantity(value, K) {
  K = K || 1024;

  var M = K*K;
  var G = M*K;
  var T = G*K;

  if (K !== 1024 && K !== 1000) {
    throw new Error("Unknown number system");
  }

  var t = _.detect([[T,'T'],[G,'G'],[M,'M'],[K,'K']], function (t) {
    return value >= t[0];
  }) || [1, ''];

  if (K === 1024) {
    t[1] += t[1] ? 'iB' : 'B';
  }

  return t;
}

function mnFormatQuantity(value, numberSystem, spacing) {
  if (!value && !_.isNumber(value)) {
    return value;
  }
  if (!spacing) {
    spacing = '';
  }
  if (numberSystem === 1000 && value <= 1100 && value % 1 === 0) { // MB-11784
    return value;
  }

  var t = mnPrepareQuantity(value, numberSystem);
  return [mnTruncateTo3Digits(value/t[0], undefined, "floor"), spacing, t[1]].join('');
}

const angularJSLikeFilter = (collection, searchTerm) => {
  return collection.filter(item =>
    Object.values(item).some(value =>
      value.toString().toLowerCase().includes(searchTerm.toLowerCase())
    )
  );
};


export { jQueryLikeParamSerializerFilter, angularJSLikeFilter, mnFormatStorageMode, mnFormatQuantity, mnPrepareQuantity, mnTruncateTo3Digits };