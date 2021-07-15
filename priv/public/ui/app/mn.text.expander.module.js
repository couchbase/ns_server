/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {MnTextExpanderComponent} from './mn.text.expander.component.js';
import {NgModule} from '../web_modules/@angular/core.js';
import {CommonModule} from '../web_modules/@angular/common.js';
import {MnPipesModule} from './mn.pipes.module.js';

export {MnTextExpanderModule}

class MnTextExpanderModule {
  static get annotations() { return [
    new NgModule({
      imports:[
        CommonModule,
        MnPipesModule
      ],
      declarations: [
        MnTextExpanderComponent
      ],
      exports: [
        MnTextExpanderComponent
      ]
    })
  ]}
}
