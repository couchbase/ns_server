/*
  Copyright 2021-Present Couchbase, Inc.

  Use of this software is governed by the Business Source License included in
  the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
  file, in accordance with the Business Source License, use of this software
  will be governed by the Apache License, Version 2.0, included in the file
  licenses/APL2.txt.
*/

import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { MnTruncate } from './mn.pipes.js';

class MnTextExpander extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      toggleState: false,
      isOverLimit: false,
    };
  }

  componentDidMount() {
    const { text, limit } = this.props;

    this.toggler = MnHelperService.createToggle();
    this.toggleState = this.toggler.state;
    MnHelperReactService.async(this, 'toggleState');

    this.isOverLimit = text && text.length > parseInt(limit, 10);
  }

  render() {
    const { text, limit } = this.props;
    const { toggleState } = this.state;

    return (
      <>
        <span className="pre-line">
          {MnTruncate.transform(text, toggleState ? Infinity : limit, '')}
        </span>
        {this.isOverLimit && (
          <a onClick={() => this.toggler.click.next()}>
            {toggleState ? ' hide' : ' show...'}
          </a>
        )}
      </>
    );
  }
}

export { MnTextExpander };
