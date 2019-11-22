import { MnAppComponent } from './mn.app.component.js';
import { MnAppService } from './mn.app.service.js';
import { mnAppImports } from './mn.app.imports.js';
import { NgModule } from '../web_modules/@angular/core.js';
import { UIView } from '../web_modules/@uirouter/angular.js';

export { MnAppModule };

class MnAppModule {
  static annotations = [
    new NgModule({
      declarations: [
        MnAppComponent
      ],
      imports: mnAppImports,
      bootstrap: [
        UIView
      ],
      providers: [
        MnAppService
      ]
    })
  ]

  static parameters = [
    MnAppService
  ]

  constructor(mnAppService) {
  }
}
