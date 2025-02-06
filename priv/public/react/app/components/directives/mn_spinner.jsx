/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import React from 'react';

const MnSpinner = ({ children, mnSpinner, minHeight, opacity }) => {
  const spinnerStyle = minHeight ? { minHeight } : {};

  return (
    <div className="relative">
      {children}
      <div
        className={`spinner${opacity ? ' opacity' : ''}`}
        style={spinnerStyle}
        hidden={!mnSpinner}
      />
    </div>
  );
};

export { MnSpinner };
