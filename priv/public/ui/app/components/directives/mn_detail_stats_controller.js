import mnStatisticsNewService from "/ui/app/mn_admin/mn_statistics_service.js";
import mnStatisticsDescriptionService from "/ui/app/mn_admin/mn_statistics_description_service.js";
import mnStatisticsChart from "/ui/app/mn_admin/mn_statistics_chart_directive.js";
import mnHelper from "/ui/app/components/mn_helper.js";

export default 'mnDetailStatsModule';

angular
  .module('mnDetailStatsModule', [
    mnStatisticsNewService,
    mnStatisticsDescriptionService,
    mnStatisticsChart,
    mnHelper
  ])
  .component('mnDetailStats', {
    bindings: {
      mnTitle: "@",
      bucket: "@",
      itemId: "@",
      service: "@",
      prefix: "@",
      nodeName: "@?"
    },
    template: "<ng-include src=\"'/ui/app/components/directives/mn_detail_stats.html'\"></ng-include>",
    controller: controller
  });

function controller(mnStatisticsNewService, mnStatisticsDescriptionService, mnHelper) {
  var vm = this;
  vm.zoom = "minute";
  vm.onSelectZoom = onSelectZoom;
  vm.items = {};
  vm.$onInit = activate;

  function onSelectZoom() {
    activate();
  }

  function getStats(stat) {
    var rv = {};
    rv["@" + vm.service + "-.@items." + stat] = true;
    return rv;
  }

  function activate() {
    mnStatisticsNewService.heartbeat.setInterval(
      mnStatisticsNewService.defaultZoomInterval(vm.zoom));
    vm.items[vm.service] = vm.prefix + "/" + vm.itemId + "/";
    vm.charts = Object
      .keys(mnStatisticsDescriptionService.stats["@" + vm.service + "-"]["@items"])
      .filter(function (key) {
        return mnStatisticsDescriptionService.stats["@" +vm.service+"-"]["@items"][key];
      })
      .map(function (stat) {
        return {
          node: vm.nodeName,
          preset: true,
          id: mnHelper.generateID(),
          isSpecific: false,
          size: "small",
          stats: getStats(stat)
        };
      });
  }
}
