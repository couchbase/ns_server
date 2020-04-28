import { NgModule } from '/ui/web_modules/@angular/core.js';
import { CommonModule } from '/ui/web_modules/@angular/common.js';
import { UIRouterModule } from "/ui/web_modules/@uirouter/angular.js";

import { MnCollectionsComponent } from './mn.collections.component.js';
import { MnCollectionsService } from './mn.collections.service.js';
import { MnSharedModule } from './mn.shared.module.js';

let collectionsState = {
  url: '/collections',
  name: "app.admin.collections",
  data: {
    permissions: "cluster.bucket['.'].collections.read",
    title: "Scopes & Collections",
    child: "app.admin.buckets",
    compat: "atLeast70"
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
        CommonModule,
        MnSharedModule,
        UIRouterModule.forChild({ states: [collectionsState] })
      ],
      providers: [
        MnCollectionsService
      ]
    })
  ]}
}
