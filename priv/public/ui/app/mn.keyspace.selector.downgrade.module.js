import angular from "/ui/web_modules/angular.js";
import {downgradeComponent,
        downgradeInjectable} from"/ui/web_modules/@angular/upgrade/static.js";
import {MnKeyspaceSelectorComponent} from "/ui/app/mn.keyspace.selector.component.js";
import {MnCollectionsService} from '/ui/app/mn.collections.service.js';
import {Subject, of} from "/ui/web_modules/rxjs.js";

export default "mnKeyspaceSelectorDowngradeModule";

angular
  .module('mnKeyspaceSelectorDowngradeModule', [])
  .factory('mnCollectionsServiceDowngrade', downgradeInjectable(MnCollectionsService))
  .directive('mnKeyspaceSelectorDowngrade', downgradeComponent({
    component: MnKeyspaceSelectorComponent
  }));
