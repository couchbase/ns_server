/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { BehaviorSubject, Subject } from 'rxjs';
import {
  distinctUntilChanged,
  withLatestFrom,
  takeUntil,
  map,
  pluck,
} from 'rxjs/operators';
import { Component } from 'react';
import mitt from 'mitt';

export { MnLifeCycleHooksToStream, DetailsHashObserver, singletonGuard };

const reactComponentLifecycleHooks = {
  OnInit: 'componentDidMount',
  OnChanges: 'componentDidUpdate',
  OnDestroy: 'componentWillUnmount',
};

const angularComponentLifecycleHooks = ['OnChanges', 'OnInit', 'OnDestroy'];

class MnLifeCycleHooksToStream extends Component {
  constructor() {
    super();
    this.emitter = mitt();
    angularComponentLifecycleHooks.forEach((name) => {
      //OnChanges triggers before OnInit, so we should keep current value
      this['mn' + name] =
        name === 'OnChanges' ? new BehaviorSubject() : new Subject();
    });
  }
  $on(event, handler) {
    this.emitter.on(event, handler);
  }
  $broadcast(event, data) {
    this.rootEmitter.emit(event, data);
  }
}

angularComponentLifecycleHooks.forEach(function (name) {
  if (name === 'OnDestroy') {
    MnLifeCycleHooksToStream.prototype[reactComponentLifecycleHooks[name]] =
      function (value) {
        this['mn' + name].next();
        this['mn' + name].complete(value);
        this.emitter.emit('$destroy', value);
      };
  } else {
    MnLifeCycleHooksToStream.prototype[reactComponentLifecycleHooks[name]] =
      function (value) {
        this['mn' + name].next({ currentValue: this.props });
      };
  }
});

class DetailsHashObserver {
  constructor(uiRouter, component, paramKey, paramValue) {
    this.uiRouter = uiRouter;
    this.component = component;
    this.paramKey = paramKey;
    this.paramValue = paramValue;

    this.stream = {};
    this.stream.toggleDetails = new Subject();

    this.stream.openedDetailsHash = this.uiRouter.globals.params$.pipe(
      pluck(this.paramKey),
      distinctUntilChanged()
    );

    this.stream.isOpened = this.stream.openedDetailsHash.pipe(
      map(this.isOpened.bind(this))
    );

    this.stream.newHashValue = this.stream.toggleDetails.pipe(
      withLatestFrom(this.stream.openedDetailsHash),
      map(this.getNewHashValue.bind(this))
    );

    this.stream.newHashValue
      .pipe(takeUntil(this.component.mnOnDestroy))
      .subscribe(this.setNewHashValue.bind(this));
  }

  setNewHashValue(newHashValue) {
    var stateParams = {};
    stateParams[this.paramKey] = newHashValue;
    this.uiRouter.stateService.go('.', stateParams, { notify: false });
  }

  getNewHashValue([toggleValue, values = []]) {
    values = [...values];
    if (this.isOpened(values)) {
      values.splice(values.indexOf(toggleValue), 1);
    } else {
      values.push(toggleValue);
    }
    return values;
  }

  isOpened(values = []) {
    return values.indexOf(this.paramValue) > -1;
  }
}

let singletonsMap = {};
function singletonGuard(type) {
  if (singletonsMap[type]) {
    throw new Error(`[${type}]: trying to create multiple instances,
      but this service should be a singleton.`);
  }
  singletonsMap[type] = true;
}

import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
dayjs.extend(utc);
export { dayjs };
