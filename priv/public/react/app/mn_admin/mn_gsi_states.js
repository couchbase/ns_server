/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { MnGsiComponent } from './mn_gsi_controller.jsx';
import { UIRouter } from '../mn.react.router.js';
import mnPermissions from '../components/mn_permissions.js';

UIRouter.transitionService.onBefore(
  {
    from: (state) => state.name !== 'app.admin.gsi',
    to: 'app.admin.gsi',
  },
  (trans) => {
    var original = Object.assign({}, trans.params());

    return mnPermissions.check().then(function (permissions) {
      let params = Object.assign({}, original);
      var indexesRead = permissions.bucketCollectionsNames['.n1ql.index!read'];

      if (!params.commonBucket && indexesRead && indexesRead[0]) {
        params.commonBucket = indexesRead[0];
      } else if (
        params.commonBucket &&
        indexesRead &&
        indexesRead.indexOf(params.commonBucket) < 0
      ) {
        params.commonBucket = indexesRead[0];
      } else if (params.commonBucket && (!indexesRead || !indexesRead[0])) {
        params.commonBucket = null;
      }

      if (params.commonBucket && !params.commonScope) {
        params.commonScope = '_default';
      }
      if (!params.commonBucket) {
        params.commonScope = null;
      }

      if (
        original.commonBucket !== params.commonBucket ||
        original.commonScope !== params.commonScope
      ) {
        return trans.router.stateService.target('app.admin.gsi', params);
      }
    });
  }
);

let gsiState = {
  name: 'app.admin.gsi',
  url: '/index?openedIndex&perIndexPage&perNodePage&indexesView',
  params: {
    openedIndex: {
      array: true,
      dynamic: true,
    },
    indexesView: {
      value: 'viewByIndex',
      dynamic: true,
    },
    footerBucket: {
      value: null,
      dynamic: true,
    },
    perNodePage: {
      value: {},
      type: 'json',
      dynamic: true,
    },
    perIndexPage: {
      value: { page: 1, size: 15 },
      type: 'json',
      dynamic: true,
    },
  },
  component: MnGsiComponent,
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

export const states = [gsiState];
