/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {MnLogsCollectInfoComponent} from "./mn.logs.collectInfo.component.js";
import {MnLogsCollectInfoFormComponent} from './mn.logs.collectInfo.form.component.js';
import {MnLogsCollectInfoResultComponent} from './mn.logs.collectInfo.result.component.js';
import {MnLogsCollectInfoStopCollectionComponent} from './mn.logs.collectInfo.stop.collection.component.js';
import {MnClusterSummaryDialogComponent} from './mn.cluster.summary.dialog.component.js';
import {MnLogsCollectInfoService} from './mn.logs.collectInfo.service.js';
import {NgModule} from '/ui/web_modules/@angular/core.js';
import {NgbModule} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {CommonModule} from '/ui/web_modules/@angular/common.js';
import {ClipboardModule} from '/ui/web_modules/ngx-clipboard.js';
import {MnSharedModule} from './mn.shared.module.js';
import {MnPipesModule} from "./mn.pipes.module.js";
import {ReactiveFormsModule} from '/ui/web_modules/@angular/forms.js';
import {UIRouterModule} from "/ui/web_modules/@uirouter/angular.js";
import {MnSelectableNodesModule} from "./mn.selectable.nodes.module.js";


let states = [
  {
    url: "/collectInfo",
    abstract: true,
    name: "app.admin.logs.collectInfo",
    component: MnLogsCollectInfoComponent,
    data: {
      permissions: "cluster.admin.logs.read",
      title: "Collect Information"
    }
  },
  {
    url: "/form",
    name: "app.admin.logs.collectInfo.form",
    component: MnLogsCollectInfoFormComponent
  },
  {
    url: "/result",
    name: "app.admin.logs.collectInfo.result",
    component: MnLogsCollectInfoResultComponent
  }
];

export {MnLogsCollectInfoModule}

class MnLogsCollectInfoModule {
  static get annotations() { return [
    new NgModule({
      imports: [
        CommonModule,
        NgbModule,
        MnSelectableNodesModule,
        ReactiveFormsModule,
        MnSharedModule,
        ClipboardModule,
        MnPipesModule,
        UIRouterModule.forChild({ states: states })
      ],
      declarations: [
        MnLogsCollectInfoComponent,
        MnLogsCollectInfoFormComponent,
        MnLogsCollectInfoResultComponent,
        MnLogsCollectInfoStopCollectionComponent,
        MnClusterSummaryDialogComponent
      ],
      entryComponents: [
        MnLogsCollectInfoStopCollectionComponent,
        MnClusterSummaryDialogComponent
      ],
      exports: [
        MnLogsCollectInfoFormComponent,
        MnLogsCollectInfoResultComponent
      ],
      providers: [
        MnLogsCollectInfoService
      ]
    })
  ]}
}
