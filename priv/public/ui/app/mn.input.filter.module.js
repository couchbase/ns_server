import {MnInputFilterComponent} from './mn.input.filter.component.js';
import {NgModule} from '/ui/web_modules/@angular/core.js';
import {CommonModule} from '/ui/web_modules/@angular/common.js';
import {ReactiveFormsModule} from '/ui/web_modules/@angular/forms.js';

export {MnInputFilterModule}

class MnInputFilterModule {
  static get annotations() { return [
    new NgModule({
      imports: [
        ReactiveFormsModule,
        CommonModule
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
