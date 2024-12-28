import _ from 'lodash';
import mnAlertsService from './mn_alerts.js';
import mnHelper from './mn_helper.js';
import { MnHelperReactService } from '../mn.helper.react.service.js';

const mnPromiseHelper = (scope, promise, modalInstance) => {
  let spinnerNameOrFunction = 'viewLoading';
  let errorsNameOrCallback = 'errors';
  let pendingGlobalSpinnerQueries = {};
  let spinnerTimeout;
  const promiseHelper = {
    applyToScope,
    getPromise,
    onSuccess,
    reloadState,
    closeFinally,
    closeOnSuccess,
    showErrorsSensitiveSpinner,
    catchErrorsFromSuccess,
    showSpinner,
    showGlobalSpinner,
    catchErrors,
    catchGlobalErrors,
    showGlobalSuccess,
    broadcast,
    removeErrors,
    closeModal
  };

  return promiseHelper;

  function getPromise() {
    return promise;
  }
  function onSuccess(cb) {
    promise.then(cb);
    return this;
  }
  function reloadState(state) {
    promise.then(() => {
      spinnerCtrl(true);
      mnHelper.reloadState(state);
    });
    return this;
  }
  function closeFinally() {
    promise.finally(closeModal);
    return this;
  }
  function closeOnSuccess() {
    promise.then(closeModal);
    return this;
  }
  function showErrorsSensitiveSpinner(name, timer) {
    name && setSpinnerName(name);
    maybeHandleSpinnerWithTimer(timer);
    promise.then(clearSpinnerTimeout, hideSpinner);
    return this;
  }
  function catchErrorsFromSuccess(nameOrCallback) {
    nameOrCallback && setErrorsNameOrCallback(nameOrCallback);
    promise.then((resp) => {
      errorsCtrl(extractErrors(resp));
    });
    return this;
  }
  function showSpinner(name, timer) {
    name && setSpinnerName(name);
    maybeHandleSpinnerWithTimer(timer);
    promise.then(hideSpinner, hideSpinner);
    return this;
  }
  function showGlobalSpinner() {
    const id = doShowGlobalSpinner();
    promise.then(hideGlobalSpinner(id), hideGlobalSpinner(id));
    return this;
  }
  function catchErrors(nameOrCallback) {
    nameOrCallback && setErrorsNameOrCallback(nameOrCallback);
    promise.then(removeErrors, (resp) => {
      if (resp.status !== -1) {
        errorsCtrl(extractErrors(resp));
      }
    });
    return this;
  }
  function catchGlobalErrors(errorMessage, timeout) {
    promise.then(null, (resp) => {
      if (resp.status !== -1) {
        mnAlertsService.formatAndSetAlerts(errorMessage || extractErrors(resp.data), 'error', timeout);
      }
    });
    return this;
  }
  function showGlobalSuccess(successMessage, timeout = 2500) {
    promise.then((resp) => {
      mnAlertsService.formatAndSetAlerts(successMessage || resp.data, 'success', timeout);
    });
    return this;
  }
  function applyToScope(keyOrFunction) {
    promise.then(_.isFunction(keyOrFunction) ? keyOrFunction : (value) => {
      scope.setState({[keyOrFunction]: value});
    }, () => {
      if (_.isFunction(keyOrFunction)) {
        keyOrFunction(null);
      } else {
        scope.setState({[keyOrFunction]: null});
      }
    });
    return this;
  }
  function broadcast($rootScope, event, data) {
    promise.then(() => {
      $rootScope.$broadcast(event, data);
    });
    return this;
  }
  function spinnerCtrl(isLoaded) {
    if (_.isFunction(spinnerNameOrFunction)) {
      spinnerNameOrFunction(isLoaded);
    } else {
      scope.setState({[spinnerNameOrFunction]: isLoaded});
    }
  }
  function errorsCtrl(errors) {
    if (_.isFunction(errorsNameOrCallback)) {
      errorsNameOrCallback(errors);
    } else {
      scope.setState({[errorsNameOrCallback]: errors});
    }
  }
  function doShowGlobalSpinner() {
    const timer = setTimeout(() => {
      MnHelperReactService.mnGlobalSpinnerFlag.next(true);
    }, 100);
    const id = "id" + Math.random().toString(36).substr(2, 9);
    pendingGlobalSpinnerQueries[id] = timer;
    return id;
  }
  function hideGlobalSpinner(id) {
    return () => {
      clearTimeout(pendingGlobalSpinnerQueries[id]);
      delete pendingGlobalSpinnerQueries[id];
      if (_.isEmpty(pendingGlobalSpinnerQueries)) {
        MnHelperReactService.mnGlobalSpinnerFlag.next(false);
      }
    };
  }
  function hideSpinner() {
    spinnerCtrl(false);
    clearSpinnerTimeout();
  }
  function removeErrors() {
    errorsCtrl(false);
    return this;
  }
  function setSpinnerName(name) {
    spinnerNameOrFunction = name;
  }
  function setErrorsNameOrCallback(nameOrCallback) {
    errorsNameOrCallback = nameOrCallback;
  }
  function closeModal() {
    //TODO: think about this
    //mostlikely it should be onClose
    modalInstance.close(scope);
  }
  function extractErrors(resp) {
    if (resp.status === 0) {
      return false;
    }
    const errors = resp.data && resp.data.errors !== undefined && _.keys(resp.data).length === 1 ? resp.data.errors : resp.data || resp;
    return _.isEmpty(errors) ? false : errors;
  }
  function clearSpinnerTimeout() {
    if (spinnerTimeout) {
      clearTimeout(spinnerTimeout);
    }
  }
  function enableSpinnerTimeout(timer) {
    spinnerTimeout = setTimeout(() => {
      spinnerCtrl(true);
    }, timer);
  }
  function maybeHandleSpinnerWithTimer(timer) {
    if (timer) {
      enableSpinnerTimeout(timer);
      scope.mnOnDestroy && scope.mnOnDestroy.subscribe(clearSpinnerTimeout);
    } else {
      spinnerCtrl(true);
    }
  }
};

export default mnPromiseHelper;
