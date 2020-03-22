// import app from "./app.js";

import { platformBrowserDynamic } from '/ui/web_modules/@angular/platform-browser-dynamic.js';

import { MnAppModule } from './mn.app.module.js';

platformBrowserDynamic().bootstrapModule(MnAppModule);
