/*
Copyright 2023-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { MnSecuritySamlComponent } from './mn.security.saml.component.jsx';

let samlState = {
  url: '/saml',
  name: 'app.admin.security.saml',
  data: {
    permissions: ({ cluster }) =>
      cluster.admin.security.external.read || cluster.admin.users.external.read,
    enterprise: true,
    compat: ({ compat }) => compat.atLeast76,
  },
  component: MnSecuritySamlComponent,
};

export const states = [samlState];
