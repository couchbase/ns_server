import angular from "/ui/web_modules/angular.js";

export default "mnPeriod";

angular
  .module('mnPeriod', [])
  .directive('mnPeriod', mnPeriodDirective);

function mnPeriodDirective() {
  var mnPeriod = {
    restrict: 'A',
    scope: {
      mnPeriod: "@",
      autoCompactionSettings: '=',
      errors: "=",
      rbac: "="
    },
    templateUrl: 'app/components/directives/mn_period/mn_period.html'
  };

  return mnPeriod;
}
