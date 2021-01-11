import angular from "/ui/web_modules/angular.js";
import {downgradeComponent,
        downgradeInjectable} from"/ui/web_modules/@angular/upgrade/static.js";
import {MnKeyspaceSelectorComponent} from "/ui/app/mn.keyspace.selector.component.js";
import {MnCollectionsService} from '/ui/app/mn.collections.service.js';
import {Subject, of} from "/ui/web_modules/rxjs.js";

export default "mnKeyspaceSelector";

angular
  .module('mnKeyspaceSelector', [])
  .factory('mnCollectionsService', downgradeInjectable(MnCollectionsService))
  .directive('mnKeyspaceSelector', downgradeComponent({
    component: MnKeyspaceSelectorComponent
  }));
