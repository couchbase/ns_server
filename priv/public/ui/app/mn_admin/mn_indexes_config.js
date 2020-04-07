import angular from "/ui/web_modules/angular.js";

import mnViews from "./mn_views_controller.js";
import mnGsi from "./mn_gsi_controller.js";
import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";

export default "mnIndexes";

angular
  .module('mnIndexes', [
    mnViews,
    mnGsi,
    mnElementCrane
  ])
  .config(mnIndexesConfig);

function mnIndexesConfig($stateProvider, mnPluggableUiRegistryProvider) {


  }
}
