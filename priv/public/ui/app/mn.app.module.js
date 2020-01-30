import app from "./app.js";

import { NgModule } from '../web_modules/@angular/core.js';
import { BrowserModule } from '../web_modules/@angular/platform-browser.js';
import { UpgradeModule } from '../web_modules/@angular/upgrade/static.js';


export { MnAppModule };

class MnAppModule {
  static annotations = [
    new NgModule({
      imports: [
        BrowserModule,
        UpgradeModule
      ]
    })
  ]

  static parameters = [UpgradeModule]

  ngDoBootstrap() {
    this.upgrade.bootstrap(document, [app], { strictDi: false });
  }

  constructor(upgrade) {
    this.upgrade = upgrade;
  }

}
