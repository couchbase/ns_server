/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { UIRouter } from 'mn.react.router';
import { BehaviorSubject } from 'rxjs';
const state = {
  export: new BehaviorSubject({
    isActive: false,
    isReload: false,
    repeatAt: 60,
  }),
  interval: null,
};

const mnLostConnectionService = {
  activate,
  deactivate,
  getState,
  resendQueries,
  export: state.export,
};

function activate() {
  if (state.export.getValue().isActive) {
    return;
  }
  state.export.next({ ...state.export.getValue(), isActive: true });
  resetTimer();
  runTimer();
}

function runTimer() {
  state.interval = setInterval(function () {
    state.export.next({
      ...state.export.getValue(),
      repeatAt: state.export.getValue().repeatAt - 1,
    });
    if (state.export.getValue().repeatAt <= 0) {
      // TODO: have a look at this
      // $uibModalStack.dismissAll();
      resendQueries();
    }
  }, 1000);
}

function resetTimer() {
  if (state.interval) {
    clearInterval(state.interval);
    state.interval = null;
  }
  state.export.next({ ...state.export.getValue(), repeatAt: 60 });
}

function resendQueries() {
  // Note: $state.reload() needs to be replaced with appropriate React router functionality
  // This is a placeholder that mimics the original behavior
  UIRouter.stateService
    .reload()
    .then(deactivate)
    .catch(() => {
      resetTimer();
      runTimer();
    });
}

function deactivate() {
  if (state.export.getValue().isReload) {
    return;
  }
  state.export.next({ ...state.export.getValue(), isReload: true });
  if (state.interval) {
    clearInterval(state.interval);
  }
  window.location.reload(true); // completely reinitialize application after lost of connection
}

function getState() {
  return state;
}

export default mnLostConnectionService;
