import app from "./app.js";

import { platformBrowserDynamic } from '../web_modules/@angular/platform-browser-dynamic.js';

import { MnAppModule } from './mn.app.module.js';

document.addEventListener('DOMContentLoaded', function () {
  platformBrowserDynamic().bootstrapModule(MnAppModule);
});
