import angular from "/ui/web_modules/angular.js";

import mnStatsDescription from "./mn_statistics_description.js";
import mnPoolDefault from "/ui/app/components/mn_pool_default.js";

export default "mnStatisticsDescriptionService";

angular
  .module('mnStatisticsDescriptionService', [
    mnPoolDefault
  ])
  .factory('mnStatisticsDescriptionService', mnStatisticsDescriptionFactory);

function mnStatisticsDescriptionFactory(mnPoolDefault) {
  return {
    getStats: getStats,
    getKvGroups: getKvGroups
  };

  function getStats() {
    return mnPoolDefault.export.compat.atLeast70 ?
      mnStatsDescription["7.0"].stats :
      mnStatsDescription["6.5"].stats;
  }

  function getKvGroups() {
    return mnPoolDefault.export.compat.atLeast70 ?
      mnStatsDescription["7.0"].kvGroups :
      mnStatsDescription["6.5"].kvGroups;
  }
}
