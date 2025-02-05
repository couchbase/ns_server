/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { MnLogsComponent } from './mn.logs.component.jsx';
import { MnLogsListComponent } from './mn.logs.list.component.jsx';
import { MnLogsCollectInfoFormComponent } from './mn.logs.collectInfo.form.component.jsx';
import { MnLogsCollectInfoResultComponent } from './mn.logs.collectInfo.result.component.jsx';
import { MnLogsCollectInfoComponent } from './mn.logs.collectInfo.component.jsx';

export const states = [
  {
    name: 'app.admin.logs',
    url: '/logs',
    abstract: true,
    component: MnLogsComponent,
    data: {
      title: 'Logs',
    },
  },
];
