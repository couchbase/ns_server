import {NgZone} from '/ui/web_modules/@angular/core.js';
import {platformBrowserDynamic} from '/ui/web_modules/@angular/platform-browser-dynamic.js';
import {MnAppModule} from './mn.app.module.js';
import {UIRouter} from '/ui/web_modules/@uirouter/core.js';

platformBrowserDynamic().bootstrapModule(MnAppModule).then(platformRef => {
  const urlService = platformRef.injector.get(UIRouter).urlService;
  // Instruct UIRouter to listen to URL changes
  function startUIRouter() {
    urlService.listen();
    urlService.sync();
  }
  platformRef.injector.get(NgZone).run(startUIRouter);
});
