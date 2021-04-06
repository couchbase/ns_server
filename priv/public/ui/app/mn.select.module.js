import { MnSelectComponent } from './mn.select.component.js';
import { NgModule } from '/ui/web_modules/@angular/core.js';
import { CommonModule } from '/ui/web_modules/@angular/common.js';
import { MnSharedModule } from './mn.shared.module.js';
import { NgbModule } from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import { MnInputFilterModule } from './mn.input.filter.module.js';

export { MnSelectModule }

class MnSelectModule {
  static get annotations() { return [
    new NgModule({
      imports: [
        CommonModule,
        MnSharedModule,
        NgbModule,
        MnInputFilterModule
      ],
      declarations: [
        MnSelectComponent
      ],
      exports: [
        MnSelectComponent
      ]
    })
  ]}
}
