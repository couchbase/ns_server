/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {NgModule} from '../web_modules/@angular/core.js';
import {UIRouterModule} from "../web_modules/@uirouter/angular.js";
import {MnSharedModule} from './mn.shared.module.js';
import {ReactiveFormsModule} from '../web_modules/@angular/forms.js';

import {MnSettingsSampleBucketsComponent} from './mn.settings.sample.buckets.component.js';
import {MnSettingsSampleBucketsService} from './mn.settings.sample.buckets.service.js';
import {MnElementCraneModule} from "./mn.element.crane.js";
import {MnPipesModule} from "./mn.pipes.module.js";


const sampleBucketsState = {
  url: "/sampleBuckets",
  name: "app.admin.settings.sampleBuckets",
  component: MnSettingsSampleBucketsComponent,
  data: {
    permissions: "cluster.admin.security.read"
  }
};

export {MnSettingsSampleBucketsModule};

class MnSettingsSampleBucketsModule {
  static get annotations() { return [
    new NgModule({
      entryComponents: [],
      declarations: [
        MnSettingsSampleBucketsComponent
      ],
      imports: [
        MnSharedModule,
        MnElementCraneModule,
        UIRouterModule.forChild({ states: [sampleBucketsState] }),
        ReactiveFormsModule,
        MnPipesModule
      ],
      providers: [
        MnSettingsSampleBucketsService
      ]
    })
  ]}
}
