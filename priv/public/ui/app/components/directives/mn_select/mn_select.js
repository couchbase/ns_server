import angular from "/ui/web_modules/angular.js";

import mnSearch from "/ui/app/components/directives/mn_search/mn_search_directive.js";

export default "mnSelect";

angular
  .module("mnSelect", [
    mnSearch
  ])
  .directive("mnSelect", mnSelectDirective);

function mnSelectDirective() {
  var mnSelect = {
    restrict: "AE",
    require: ["mnSelect", "ngModel"],
    scope: {
      values: "=",
      labels: "=",
      ngModel: "=",
      onSelect: "&",
      mnDisabled: "=",
      valuesMapping: "=?",
      capitalize: "=",
      openOnTop: "=",
      mnHorizontalAlign: "=?",
      hasSearch: "=?"
    },
    templateUrl: "app/components/directives/mn_select/mn_select.html",
    link: ($scope, $element, $attributes, controllers) => {
      controllers[0].setNgModelCtl(controllers[1]);
    },
    controller: mnSelectController,
    controllerAs: "vm",
    bindToController: true
  };

  return mnSelect;

  function mnSelectController($scope, $element, $attrs) {
    var vm = this;
    var searchMinimumOptionsNumber = 10;

    var ngModelCtl;
    vm.setNgModelCtl = (ctl) => (ngModelCtl = ctl);

    if (!$attrs['valuesMapping']) {
      vm.valuesMapping = defaultValuesMapping;
    }
    if (!$attrs['mnHorizontalAlign']) {
      vm.mnHorizontalAlign = "left";
    }

    vm.mnSearchValue = "";
    vm.isOpened = false;
    vm.optionClicked = optionClicked;
    vm.clickSearch = clickSearch;
    vm.getPreparedValues = getPreparedValues;
    vm.hasSearchInput = hasSearchInput;

    /**
     * Default values mapping:
     * * if capitalize input flag is true - capitalize the displayed option if it is a string
     * * else leave the option as it is
     * @param option
     * @returns {string}
     */
    function defaultValuesMapping(option) {
      if (vm.capitalize && angular.isString(option) && option) {
        return option.charAt(0).toUpperCase() + option.slice(1);
      }

      return option;
    }

    function getPreparedValues() {
      vm.preparedValues = vm.labels ? vm.labels : (vm.values || []).map(vm.valuesMapping);
      return vm.preparedValues;
    }

    function optionClicked(value) {
      vm.onSelect && vm.onSelect({selectedOption: value});
      ngModelCtl.$setViewValue(value);
      vm.isOpened = !vm.isOpened;

      if (vm.hasSearchInput()) {
        vm.mnSearchValue = "";
      }
    }

    function clickSearch(event) {
      event.stopPropagation();
    }

    function hasSearchInput() {
      return (vm.hasSearch && (vm.values || []).length >= searchMinimumOptionsNumber) || false;
    }
  }
}
