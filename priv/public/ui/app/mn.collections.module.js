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
import { MnSharedModule } from './mn.shared.module.js';
import { MnInputFilterModule } from './mn.input.filter.module.js';
import { MnBucketsService } from './mn.buckets.service.js';
import { MnCollectionsAddScopeComponent } from './mn.collections.add.scope.component.js';
import { MnCollectionsDeleteScopeComponent } from './mn.collections.delete.scope.component.js';
import { MnCollectionsAddItemComponent} from './mn.collections.add.item.component.js';
import { MnCollectionsDeleteItemComponent} from './mn.collections.delete.item.component.js';

let collectionsState = {
  url: '/collections?collectionsBucket&scopeDetails&scopesPage&collsPage',
  name: "app.admin.collections",
  data: {
    permissions: "cluster.bucket['.'].settings.read && cluster.bucket['.'].collections.read",
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
    },
    scopesPage: {
      value: {page:1, size:9},
      type: 'json',
      dynamic: true
    },
    collsPage: {
      value: {},
      type: 'json',
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
        MnCollectionsDeleteScopeComponent,
        MnCollectionsAddItemComponent,
        MnCollectionsDeleteItemComponent
      ],
      declarations: [
        MnCollectionsComponent,
        MnCollectionsItemComponent,
        MnCollectionsScopeComponent,
        MnCollectionsScopeDetailsComponent,
        MnCollectionsAddScopeComponent,
        MnCollectionsDeleteScopeComponent,
        MnCollectionsAddItemComponent,
        MnCollectionsDeleteItemComponent
      ],
      imports: [
        NgbModule,
        MnElementCraneModule,
        ReactiveFormsModule,
        MnSharedModule,
        MnInputFilterModule,
        UIRouterModule.forChild({ states: [collectionsState] })
      ],
      providers: [
        MnCollectionsService,
        MnBucketsService
      ]
    })
  ]}
}
