/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import _ from 'lodash';

import Deferred from './mn_defered.js';
import mnPromiseHelper from './mn_promise_helper.js';
import { MnHelperReactService } from '../mn.helper.react.service';

function mnPollerFactory() {
  function Poller(scope, request, doNotListenVisibilitychange) {
    this.deferred = new Deferred();
    this.request = request;
    this.scope = scope;

    var self = this;
    function onVisibilitychange() {
      if (document.hidden) {
        self.pause();
      } else {
        self.resume();
      }
    }

    scope.mnOnDestroy &&
      scope.mnOnDestroy.subscribe(function () {
        if (!doNotListenVisibilitychange) {
          document.removeEventListener('visibilitychange', onVisibilitychange);
        }
        self.onDestroy();
      });

    if (!doNotListenVisibilitychange) {
      document.addEventListener('visibilitychange', onVisibilitychange);
    }

    this.latestResult = undefined;
    this.stopTimestamp = undefined;
    this.extractInterval = undefined;
    this.timeout = undefined;
    this.doCallPromise = undefined;
    this.throttledReload = _.debounce(this.reload.bind(this), 100);
  }

  Poller.prototype.isStopped = isStopped;
  Poller.prototype.doCall = doCall;
  Poller.prototype.setInterval = setInterval;
  Poller.prototype.cycle = cycle;
  Poller.prototype.doCycle = doCycle;
  Poller.prototype.stop = stop;
  Poller.prototype.subscribe = subscribe;
  Poller.prototype.showSpinner = showSpinner;
  Poller.prototype.reload = reload;
  Poller.prototype.resume = resume;
  Poller.prototype.pause = pause;
  Poller.prototype.reloadOnScopeEvent = reloadOnScopeEvent;
  Poller.prototype.onDestroy = onDestroy;
  Poller.prototype.getLatestResult = getLatestResult;
  Poller.prototype.onResum = onResum;

  function onDestroy() {
    this.stop();
  }

  function getLatestResult() {
    return this.latestResult;
  }

  function isStopped(startTimestamp) {
    return !(
      this.stopTimestamp === undefined || startTimestamp >= this.stopTimestamp
    );
  }
  function reloadOnScopeEvent(eventName, vm, spinnerName) {
    var self = this;
    function action() {
      self.reload();
      if (vm) {
        self.showSpinner(vm, spinnerName);
      }
    }
    if (_.isArray(eventName)) {
      _.forEach(eventName, function (event) {
        MnHelperReactService.rootScopeEmitter.on(event, action);
      });
    } else {
      MnHelperReactService.rootScopeEmitter.on(eventName, action);
    }
    return this;
  }
  function setInterval(interval) {
    this.extractInterval = interval;
    return this;
  }
  function reload(keepLatestResult) {
    if (!keepLatestResult) {
      delete this.latestResult;
    }
    this.stop();
    this.cycle();
    return this;
  }
  function showSpinner(vm, name) {
    var self = this;
    mnPromiseHelper(vm, self.doCallPromise).showSpinner(name);
    return self;
  }
  function doCall(timestamp) {
    var self = this;
    var query = _.isFunction(self.request)
      ? self.request(self.latestResult)
      : self.request;
    query.then(
      function (result) {
        if (query !== this || self.isStopped(timestamp)) {
          return;
        }
        self.deferred.notify(result);
      }.bind(query)
    );
    return query;
  }
  function cycle() {
    if (this.isLaunched) {
      return this;
    }
    delete this.stopTimestamp;
    this.isLaunched = true;
    this.doCycle();
    return this;
  }
  function doCycle() {
    var self = this;
    var timestamp = new Date();
    self.doCallPromise = self.doCall(timestamp);

    if (self.extractInterval) {
      self.doCallPromise.then(
        function (result) {
          if (self.doCallPromise !== this || self.isStopped(timestamp)) {
            return;
          }
          var interval = _.isFunction(self.extractInterval)
            ? self.extractInterval(result)
            : self.extractInterval;
          self.timeout = setTimeout(self.doCycle.bind(self), interval);
        }.bind(self.doCallPromise)
      );
    }
    self.doCallPromise.then(null, function () {
      self.stop(); //stop cycle on any http error;
    });
    return this;
  }
  function onResum(fn) {
    this.onResumCallback = fn;
    return this;
  }
  function resume() {
    this.isPaused = false;
    if (this.state) {
      this.onResumCallback && this.onResumCallback();
      this.reload();
    }
  }
  function pause() {
    if (this.isPaused) {
      return;
    }
    this.state = this.isLaunched;
    this.isPaused = true;
    this.stop();
  }
  function stop() {
    var self = this;
    self.isLaunched = false;
    self.stopTimestamp = new Date();
    clearTimeout(self.timeout);
  }
  function subscribe(subscriber, keeper) {
    var self = this;
    self.deferred.then(
      null,
      null,
      _.isFunction(subscriber)
        ? function (value) {
            subscriber(value, self.latestResult);
            self.latestResult = value;
          }
        : function (value) {
            (keeper || self.scope).setState({ [subscriber]: value });
            self.latestResult = value;
          }
    );
    return self;
  }

  return Poller;
}

function mnEtagPollerFactory(mnPoller) {
  function EtagPoller(scope, request, doNotListenVisibilitychange) {
    mnPoller.call(this, scope, request, doNotListenVisibilitychange);
  }

  EtagPoller.prototype = Object.create(mnPoller.prototype);
  EtagPoller.prototype.constructor = EtagPoller;
  EtagPoller.prototype.cycle = cycle;

  function cycle() {
    var self = this;
    var timestamp = new Date();
    self.doCallPromise = self.doCall(timestamp);
    self.doCallPromise.then(
      function () {
        if (self.doCallPromise !== this || self.isStopped(timestamp)) {
          return;
        }
        self.cycle();
      }.bind(self.doCallPromise)
    );
    return self;
  }

  return EtagPoller;
}

const mnPoller = mnPollerFactory();
const mnEtagPoller = mnEtagPollerFactory(mnPoller);

export { mnEtagPoller, mnPoller };
