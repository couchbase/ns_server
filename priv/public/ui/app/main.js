import { platformBrowserDynamic } from '../web_modules/@angular/platform-browser-dynamic.js';
import { MnAppaModule } from './mn.app.module.js';

document.addEventListener('DOMContentLoaded', function () {
  platformBrowserDynamic().bootstrapModule(MnAppModule);
})
