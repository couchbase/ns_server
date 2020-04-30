import { NgModule } from '/ui/web_modules/@angular/core.js';
import { UIRouterModule } from "/ui/web_modules/@uirouter/angular.js";
import { ReactiveFormsModule } from '/ui/web_modules/@angular/forms.js';

import { MnCollectionsComponent } from './mn.collections.component.js';
import { MnCollectionsService } from './mn.collections.service.js';
import { MnPermissionsService } from './mn.permissions.service.js';
import { MnSharedModule } from './mn.shared.module.js';
import { MnBucketsService } from './mn.buckets.service.js';

let collectionsState = {
  url: '/collections?collectionsBucket',
  name: "app.admin.collections",
  data: {
    permissions: "cluster.bucket['.'].collections.read",
    title: "Scopes & Collections",
    child: "app.admin.buckets",
    compat: "atLeast70"
  },
  params: {
    collectionsBucket: {
      type: 'string',
      dynamic: true
    }
  },
  views: {
    "main@app.admin": {
      component: MnCollectionsComponent
    }
  }
};

export { MnCollectionsModule };

class MnCollectionsModule {
  static get annotations() { return [
    new NgModule({
      declarations: [
        MnCollectionsComponent
      ],
      imports: [
        ReactiveFormsModule,
        MnSharedModule,
        UIRouterModule.forChild({ states: [collectionsState] })
      ],
      providers: [
        MnPermissionsService,
        MnCollectionsService,
        MnBucketsService
      ]
    })
  ]}
}
