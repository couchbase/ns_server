import { NgModule } from '/ui/web_modules/@angular/core.js';
import { UIRouterModule } from "/ui/web_modules/@uirouter/angular.js";
import { ReactiveFormsModule } from '/ui/web_modules/@angular/forms.js';
import { NgbModule } from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';

import { MnElementCraneModule } from './mn.element.crane.js';

import { MnCollectionsComponent } from './mn.collections.component.js';
import { MnCollectionsItemComponent } from './mn.collections.item.component.js';
import { MnCollectionsScopeComponent } from './mn.collections.scope.component.js';
import { MnCollectionsScopeDetailsComponent } from './mn.collections.scope.details.component.js';
import { MnCollectionsService } from './mn.collections.service.js';
import { MnPermissionsService } from './mn.permissions.service.js';
import { MnSharedModule } from './mn.shared.module.js';
import { MnBucketsService } from './mn.buckets.service.js';
import { MnCollectionsAddScopeComponent } from './mn.collections.add.scope.component.js';
import { MnCollectionsDeleteScopeComponent } from './mn.collections.delete.scope.component.js';

let collectionsState = {
  url: '/collections?collectionsBucket&scopeDetails',
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
    },
    scopeDetails: {
      array: true,
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
      entryComponents: [
        MnCollectionsAddScopeComponent,
        MnCollectionsDeleteScopeComponent
      ],
      declarations: [
        MnCollectionsComponent,
        MnCollectionsItemComponent,
        MnCollectionsScopeComponent,
        MnCollectionsScopeDetailsComponent,
        MnCollectionsAddScopeComponent,
        MnCollectionsDeleteScopeComponent
      ],
      imports: [
        NgbModule,
        MnElementCraneModule,
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
