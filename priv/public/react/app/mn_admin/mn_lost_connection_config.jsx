import React from 'react';
import _ from 'lodash';
import { MnLifeCycleHooksToStream } from '../mn.core.js';
import mnLostConnectionService from './mn_lost_connection_service.js';
import { MnHelperReactService } from '../mn.helper.react.service';
import axios from 'axios';

var wantedUrls = {};

axios.interceptors.response.use(
  function (resp) {
    if (wantedUrls[resp.config.url]) {
      wantedUrls = {};
      mnLostConnectionService.deactivate();
    }
    return resp;
  },
  function (rejection) {
    if (
      rejection.code === 'ERR_NETWORK' ||
      (rejection.status <= 0 && rejection.xhrStatus == 'error')
    ) {
      //rejection caused not by us (e.g. net::ERR_CONNECTION_REFUSED)
      wantedUrls[rejection.config.url] = true;
      mnLostConnectionService.activate();
    } else {
      if (rejection.config && wantedUrls[rejection.config.url]) {
        //in order to avoid cached queries
        wantedUrls = {};
        mnLostConnectionService.deactivate();
      }
    }
    return Promise.reject(rejection);
  }
);

class MnLostConnectionComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      lost: null,
    };
  }
  componentWillMount() {
    const vm = this;
    vm.lostConnectionAt = window.location.host;
    vm.lost = mnLostConnectionService.export;
    MnHelperReactService.async(vm, 'lost');

    vm.retryNow = mnLostConnectionService.resendQueries;
  }
  render() {
    const vm = this;
    const { lost } = vm.state;
    return (
      <>
        {lost.isActive && (
          <div className="alert alert-warning text-center">
            <p>
              Lost connection to server at {vm.lostConnectionAt}. Repeating in{' '}
              {lost.repeatAt} seconds. <a onClick={vm.retryNow}>Retry now</a>
            </p>
          </div>
        )}
      </>
    );
  }
}

export { MnLostConnectionComponent };
