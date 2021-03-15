import angular from "/ui/web_modules/angular.js";

export default "mnSelect";

angular
  .module("mnSelect", [])
  .directive("mnSelect", mnSelectDirective);

function mnSelectDirective() {
  var mnSelect = {
    restrict: "AE",
    require: "ngModel",
    scope: {
      values: "=",
      labels: "=",
      ngModel: "=",
      onSelect: "&",
      ngDisabled: "=",
      filter: "=?",
      capitalize: "=",
      openOnTop: "=",
      mnHorizontalAlign: "=?"
    },
    templateUrl: "app/components/directives/mn_select/mn_select.html",
    link: mnSelectController
  };

  return mnSelect;

  function mnSelectController($scope, $element, $attrs, ngModel) {
    var vm = $scope;

    vm.filter = $attrs['filter'] ? vm.filter : (option) => defaultFilter(option);
    vm.mnHorizontalAlign = vm.mnHorizontalAlign || 'left';
    vm.isOpened = false;
    vm.optionClicked = optionClicked;

    /**
     * Default filter:
     * * if capitalize input flag is true - capitalize the displayed option if it is a string
     * * else leave the option as it is
     * @param option
     * @returns {string}
     */
    function defaultFilter(option) {
      if (vm.capitalize && angular.isString(option) && option) {
        return option[0].toUpperCase() + option.slice(1);
      }

      return option;
    }

    function optionClicked(value) {
      vm.onSelect && vm.onSelect({selectedOption: value});
      ngModel.$setViewValue(value);
      vm.isOpened = !vm.isOpened;
    }
  }
}
