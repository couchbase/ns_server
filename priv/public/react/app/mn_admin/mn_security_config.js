/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { MnSecurityComponent } from './mn.security.component.jsx';

let securityState = {
  name: 'app.admin.security',
  abstract: true,
  url: '/security',
  // views: {
  //   'main@app.admin': {
  //     controller: 'mnSecurityController as securityCtl',
  //     template: mnSecurityTemplate,
  //   },
  // },
  data: {
    permissions: ({ cluster }) => {
      return cluster.admin.security.read || cluster.admin.users.read;
    },
    title: 'Security',
  },
  component: MnSecurityComponent,
};

export const states = [securityState];
