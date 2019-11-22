import angular from "/ui/web_modules/angular.js";
import mnMemoryQuotaService from "/ui/app/components/directives/mn_memory_quota/mn_memory_quota_service.js";

export default "mnServices";

angular
  .module('mnServices', [mnMemoryQuotaService])
  .directive('mnServices', mnServicesDirective);

function mnServicesDirective(mnMemoryQuotaService) {
  var mnServices = {
    restrict: 'A',
    scope: {
      mnIsDisabled: "=?",
      config: '=mnServices',
      mnIsEnterprise: "="
    },
    templateUrl: 'app/components/directives/mn_services/mn_services.html',
    controller: controller,
    controllerAs: "mnServicesCtl",
    bindToController: true
  };

  return mnServices;
}

function controller(mnMemoryQuotaService) {
  var vm = this;
  vm.change = mnMemoryQuotaService.handleAltAndClick;
}
