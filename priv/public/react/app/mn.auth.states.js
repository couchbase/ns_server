/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {MnAuthComponent} from './mn.auth.component';

let authState = {
  name: "app.auth",
  url: '/auth',
  params: {
    samlErrorMsgId: {
      value: null,
      squash: true,
      dynamic: true
    }
  },
  component: MnAuthComponent
};

// let authChangePasswordState = {
//   name: "app.authChangePassword",
//   component: MnAuthChangePasswordComponent,
//   params: {
//     auth: {
//       value: null,
//       dynamic: true
//     }
//   },
// };

export const states = [authState];