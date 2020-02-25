import { MnFocusDirective } from './mn.focus.directive.js';
import { NgModule } from '../web_modules/@angular/core.js';
import { BrowserModule } from '../web_modules/@angular/platform-browser.js';
import { ReactiveFormsModule } from '../web_modules/@angular/forms.js';

export { MnSharedModule }

class MnSharedModule {
  static get annotations() { return [
    new NgModule({
      declarations: [
        MnFocusDirective,
        // mn.components.MnAutoCompactionForm,
        // mn.components.MnPeriod,
        // mn.components.MnServicesConfig,
        // mn.components.MnSearch,
        // mn.components.MnSearchField
      ],
      exports: [
        MnFocusDirective,
        // mn.components.MnServicesConfig,
        // mn.components.MnAutoCompactionForm,
        // mn.components.MnSearch,
        // mn.components.MnSearchField
      ],
      imports: [
        ReactiveFormsModule,
        BrowserModule,
        // ngb.NgbModule,
      ]
    })
  ]}
}
