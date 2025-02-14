/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import React from 'react';
import { MnLifeCycleHooksToStream } from 'mn.core';
import { UIView } from '@uirouter/react';

class MnSecurityComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {};
  }

  componentWillMount() {
    var vm = this;
  }

  render() {
    return (
      <div ui-view="" class="margin-top-half padding-left-1">
        <UIView />
      </div>
    );
  }
}

export { MnSecurityComponent };
