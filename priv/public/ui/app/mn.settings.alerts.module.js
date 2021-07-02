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
import { ReactiveFormsModule } from '/ui/web_modules/@angular/forms.js';
import { MnSettingsAlertsComponent } from './mn.settings.alerts.component.js';
import { MnSettingsAlertsService } from './mn.settings.alerts.service.js';

let alertsState = {
  url: "/alerts",
  name: "app.admin.settings.alerts",
  component: MnSettingsAlertsComponent,
  data: {
    permissions: "cluster.admin.security.read"
  }
};

export { MnSettingsAlertsModule };

class MnSettingsAlertsModule {
  static get annotations() { return [
    new NgModule({
      entryComponents: [],
      declarations: [
        MnSettingsAlertsComponent
      ],
      imports: [
        MnSharedModule,
        ReactiveFormsModule,
        UIRouterModule.forChild({ states: [alertsState] }),
      ],
      providers: [
        MnSettingsAlertsService
      ]
    })
  ]}
}
