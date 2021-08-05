/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { NgModule } from '/ui/web_modules/@angular/core.js';
import { UIRouterModule } from "/ui/web_modules/@uirouter/angular.js";
import { MnSharedModule } from './mn.shared.module.js';
import { MnSettingsAutoCompactionComponent } from './mn.settings.auto.compaction.component.js';
import { MnSettingsAutoCompactionService } from './mn.settings.auto.compaction.service.js';
import { MnSettingsAutoCompactionFormModule } from './mn.settings.auto.compaction.form.module.js';
import { ReactiveFormsModule } from '/ui/web_modules/@angular/forms.js';
import { MnElementCraneModule } from "./mn.element.crane.js";
import { MnHelperService } from './mn.helper.service.js';

const autoCompactionState = {
  url: "/autoCompaction",
  name: "app.admin.settings.autoCompaction",
  component: MnSettingsAutoCompactionComponent,
  data: {
    permissions: "cluster.settings.autocompaction.read"
  }
};

export { MnSettingsAutoCompactionModule };

class MnSettingsAutoCompactionModule {
  static get annotations() { return [
    new NgModule({
      declarations: [
        MnSettingsAutoCompactionComponent
      ],
      imports: [
        MnSharedModule,
        UIRouterModule.forChild({ states: [autoCompactionState] }),
        ReactiveFormsModule,
        MnElementCraneModule,
        MnSettingsAutoCompactionFormModule
      ],
      providers: [
        MnSettingsAutoCompactionService,
        MnHelperService
      ]
    })
  ]}
}
