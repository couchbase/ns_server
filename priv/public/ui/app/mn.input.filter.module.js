import {MnInputFilterComponent} from './mn.input.filter.component.js';
import {NgModule} from '/ui/web_modules/@angular/core.js';
import {CommonModule} from '/ui/web_modules/@angular/common.js';
import {ReactiveFormsModule} from '/ui/web_modules/@angular/forms.js';
import {MnSharedModule} from './mn.shared.module.js';

export {MnInputFilterModule}

class MnInputFilterModule {
  static get annotations() { return [
    new NgModule({
      imports: [
        ReactiveFormsModule,
        CommonModule,
        MnSharedModule
      ],
      declarations: [
        MnInputFilterComponent
      ],
      exports: [
        MnInputFilterComponent
      ]
    })
  ]}
}
