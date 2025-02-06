/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import _ from 'lodash';
import mnPendingQueryKeeper from './mn_pending_query_keeper.js';
import { UIRouter } from '../mn.react.router.js';
import { BehaviorSubject } from 'rxjs';
const mnHelper = {
  wrapInFunction,
  calculateMaxMemorySize,
  initializeDetailsHashObserver,
  checkboxesToList,
  reloadApp,
  reloadState,
  listToCheckboxes,
  getEndings,
  generateID,
  counterSpinner,
  mainSpinnerCounter: counterSpinner(),
};

function getEndings(length) {
  return length !== 1 ? 's' : '';
}

function counterSpinner() {
  const counter = new BehaviorSubject(0);
  return {
    increase: () => counter.next(counter.getValue() + 1),
    decrease: () => counter.next(counter.getValue() - 1),
    value: () => counter,
  };
}

function wrapInFunction(value) {
  return function () {
    return value;
  };
}

function calculateMaxMemorySize(totalRAMMegs) {
  return Math.floor(Math.max(totalRAMMegs * 0.8, totalRAMMegs - 1024));
}

function initializeDetailsHashObserver($scope, hashKey, stateName) {
  function getHashValue() {
    return _.clone(UIRouter.stateService.params[hashKey]) || [];
  }
  $scope.isDetailsOpened = function (hashValue) {
    return _.contains(getHashValue(), String(hashValue));
  };
  $scope.toggleDetails = function (hashValue) {
    var currentlyOpened = getHashValue();
    var stateParams = {};
    if ($scope.isDetailsOpened(hashValue)) {
      stateParams[hashKey] = _.difference(currentlyOpened, [String(hashValue)]);
      UIRouter.stateService.go(stateName, stateParams).then($scope.updateState);
    } else {
      currentlyOpened.push(String(hashValue));
      stateParams[hashKey] = currentlyOpened;
      UIRouter.stateService.go(stateName, stateParams).then($scope.updateState);
    }
  };
}

function checkboxesToList(object) {
  return _.chain(object).pick(_.identity).keys().value();
}

function listToCheckboxes(list) {
  return _.zipObject(
    list,
    _.fill(new Array(list.length), true, 0, list.length)
  );
}

function reloadApp() {
  window.location.reload();
}

function generateID() {
  return Math.random().toString(36).substr(2, 9);
}

function reloadState(state) {
  if (!state) {
    mnPendingQueryKeeper.cancelAllQueries();
  }
  return UIRouter.stateService.reload(state);
}

export default mnHelper;
