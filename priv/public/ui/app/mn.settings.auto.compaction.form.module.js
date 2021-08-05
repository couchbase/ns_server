/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { NgModule } from '/ui/web_modules/@angular/core.js';
import { NgbModule } from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import { MnSharedModule } from './mn.shared.module.js';
import { ReactiveFormsModule } from '/ui/web_modules/@angular/forms.js';
import { MnSettingsAutoCompactionFormComponent } from './mn.settings.auto.compaction.form.component.js';
import { MnSettingsAutoCompactionTimePeriodComponent } from './mn.settings.auto.compaction.time.period.component.js';

export { MnSettingsAutoCompactionFormModule };

class MnSettingsAutoCompactionFormModule {
  static get annotations() { return [
    new NgModule({
      imports: [
        ReactiveFormsModule,
        MnSharedModule,
        NgbModule
      ],
      declarations: [
        MnSettingsAutoCompactionFormComponent,
        MnSettingsAutoCompactionTimePeriodComponent
      ],
      exports: [
        MnSettingsAutoCompactionFormComponent,
        MnSettingsAutoCompactionTimePeriodComponent
      ]
    })
  ]}
}
