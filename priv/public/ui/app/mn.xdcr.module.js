import { NgModule } from "/ui/web_modules/@angular/core.js";
import { UIRouterModule } from "/ui/web_modules/@uirouter/angular.js";
import { ReactiveFormsModule } from "/ui/web_modules/@angular/forms.js";
import { NgbModule } from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js";

import { MnElementCraneModule } from "./mn.element.crane.js";
import { MnSharedModule } from './mn.shared.module.js';

import { MnXDCRComponent } from "./mn.xdcr.component.js";
import { MnXDCRItemComponent } from "./mn.xdcr.item.component.js";
import { MnXDCRItemDetailsComponent,
         MnReplicationStatus } from "./mn.xdcr.item.details.component.js";
import { MnXDCRRefItemComponent } from "./mn.xdcr.ref.item.component.js";
import { MnXDCRService } from "./mn.xdcr.service.js";
import { MnBucketsService } from "./mn.buckets.service.js";

import { MnXDCRAddRefComponent } from "./mn.xdcr.add.ref.component.js";
import { MnXDCRAddRepComponent } from "./mn.xdcr.add.rep.component.js";
import { MnXDCRDeleteRefComponent } from "./mn.xdcr.delete.ref.component.js";
import { MnXDCRDeleteRepComponent } from "./mn.xdcr.delete.rep.component.js";
import { MnXDCRFilterComponent } from "./mn.xdcr.filter.component.js";
import { MnXDCRSettingsComponent } from "./mn.xdcr.settings.component.js";
import { MnXDCREditRepComponent } from "./mn.xdcr.edit.rep.component.js";
import { MnXDCRErrorsComponent } from "./mn.xdcr.errors.component.js";

let XDCRState = {
  url: '/replications',
  name: "app.admin.replications",
  data: {
    permissions: "cluster.tasks.read",
    title: "XDCR Replications"
  },
  params: {
    xdcrDetails: {
      array: true,
      dynamic: true
    }
  },
  views: {
    "main@app.admin": {
      component: MnXDCRComponent
    }
  }
};

export { MnXDCRModule };

class MnXDCRModule {
  static get annotations() { return [
    new NgModule({
      entryComponents: [
        MnXDCRAddRefComponent,
        MnXDCRAddRepComponent,
        MnXDCRDeleteRefComponent,
        MnXDCRDeleteRepComponent,
        MnXDCREditRepComponent,
        MnXDCRErrorsComponent
      ],
      declarations: [
        MnXDCRComponent,
        MnXDCRItemComponent,
        MnXDCRItemDetailsComponent,
        MnXDCRRefItemComponent,
        MnXDCRAddRefComponent,
        MnXDCRAddRepComponent,
        MnXDCRDeleteRefComponent,
        MnXDCRDeleteRepComponent,
        MnXDCREditRepComponent,
        MnXDCRSettingsComponent,
        MnXDCRFilterComponent,
        MnXDCRErrorsComponent,
        MnReplicationStatus
      ],
      imports: [
        NgbModule,
        MnElementCraneModule,
        ReactiveFormsModule,
        MnSharedModule,
        UIRouterModule.forChild({ states: [XDCRState] })
      ],
      providers: [
        MnXDCRService,
        MnBucketsService
      ]
    })
  ]}
}
