/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import React from 'react';
import mnHelper from "../mn_helper.js";

export class MnMainSpinner extends React.Component {
  constructor(props) {
    super(props);
    this.initialized = false;
  }

  componentDidUpdate(prevProps) {
    const { value } = this.props;
    
    if (!this.initialized && value) {
      this.initialized = true;
    }
    
    if (!this.initialized) {
      return;
    }

    if (value && !prevProps.value) {
      mnHelper.mainSpinnerCounter.increase();
    } else if (!value && prevProps.value) {
      mnHelper.mainSpinnerCounter.decrease();
    }
  }

  componentWillUnmount() {
    if (this.initialized && this.props.value) {
      mnHelper.mainSpinnerCounter.decrease();
    }
  }

  render() {
    return null; // This component only manages the spinner counter
  }
}

MnMainSpinner.defaultProps = {
  value: false
}; 