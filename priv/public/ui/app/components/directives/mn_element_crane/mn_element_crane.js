import angular from "/ui/web_modules/angular.js";

import {MnElementCargoComponent,
        MnElementDepotComponent} from "/ui/app/mn.element.crane.js";

import {downgradeComponent} from "/ui/web_modules/@angular/upgrade/static.js";

export default "mnElementCrane";

angular
  .module('mnElementCrane', [])
  .directive('mnElementDepot', downgradeComponent({component: MnElementDepotComponent}))
  .directive('mnElementCargo', downgradeComponent({component: MnElementCargoComponent}));
