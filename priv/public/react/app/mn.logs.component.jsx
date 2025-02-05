/*
  Copyright 2021-Present Couchbase, Inc.

  Use of this software is governed by the Business Source License included in
  the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
  file, in accordance with the Business Source License, use of this software
  will be governed by the Apache License, Version 2.0, included in the file
  licenses/APL2.txt.
*/
import React from 'react';
import { UIView, UISref } from '@uirouter/react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import mnPermissions from './components/mn_permissions.js';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnLogsComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      permissions: null,
    };
  }

  componentDidMount() {
    var vm = this;

    vm.permissions = mnPermissions.stream;
    MnHelperReactService.async(vm, 'permissions');
  }

  render() {
    const { permissions } = this.state;
    return (
      <div>
        <div
          className="flex flex-center flex-gap-10"
          hidden={!permissions?.cluster?.admin?.logs?.read}
        >
          <UISref to="app.admin.logs.list">
            <a>Logs</a>
          </UISref>
          <UISref to="app.admin.logs.collectInfo.form">
            <a>Collect Information</a>
          </UISref>
        </div>
        <UIView />
      </div>
    );
  }
}

export { MnLogsComponent };
