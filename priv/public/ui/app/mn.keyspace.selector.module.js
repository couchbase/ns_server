import { NgModule } from '/ui/web_modules/@angular/core.js';
import { BrowserModule } from '/ui/web_modules/@angular/platform-browser.js';
import { ReactiveFormsModule } from '/ui/web_modules/@angular/forms.js';
import { MnKeyspaceSelectorComponent } from "/ui/app/mn.keyspace.selector.component.js";
import { MnInputFilterModule } from './mn.input.filter.module.js';
import { MnCollectionsServiceModule } from './mn.collections.service.js';

export { MnKeyspaceSelectorModule };

class MnKeyspaceSelectorModule {
  static get annotations() { return [
    new NgModule({
      entryComponents: [
        MnKeyspaceSelectorComponent
      ],
      declarations: [
        MnKeyspaceSelectorComponent
      ],
      imports: [
        BrowserModule,
        MnInputFilterModule,
        ReactiveFormsModule,
        MnCollectionsServiceModule
      ]
    })
  ]}
}
