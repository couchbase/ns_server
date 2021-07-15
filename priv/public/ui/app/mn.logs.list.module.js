/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {NgModule} from '../web_modules/@angular/core.js';
import {CommonModule, DatePipe} from '../web_modules/@angular/common.js';
import {MnSharedModule} from './mn.shared.module.js';
import {UIRouterModule} from '../web_modules/@uirouter/angular.js';
import {MnInputFilterModule} from './mn.input.filter.module.js';
import {MnTextExpanderModule} from './mn.text.expander.module.js';

import {MnLogsListService} from './mn.logs.list.service.js';
import {MnLogsListComponent} from './mn.logs.list.component.js';

let states = [{
  url: '',
  name: 'app.admin.logs.list',
  component: MnLogsListComponent
}];

export {MnLogsListModule};

class MnLogsListModule {
  static get annotations() { return [
    new NgModule({
      declarations: [
        MnLogsListComponent
      ],
      imports: [
        UIRouterModule.forChild({
          states: states
        }),
        CommonModule,
        MnInputFilterModule,
        MnTextExpanderModule,
        MnSharedModule
      ],
      providers: [
        MnLogsListService,
        DatePipe
      ]
    })
  ]}
}
