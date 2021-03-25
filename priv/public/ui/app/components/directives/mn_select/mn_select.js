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
    require: "ngModel",
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
    link: mnSelectController
  };

  return mnSelect;

  function mnSelectController($scope, $element, $attrs, ngModel) {
    var vm = $scope;

    vm.mnSearch = {value: ""};

    var searchMinimumOptionsNumber = 10;
    vm.valuesMapping = $attrs['valuesMapping'] ? vm.valuesMapping : (option) => defaultValuesMapping(option);
    vm.mnHorizontalAlign = vm.mnHorizontalAlign || 'left';
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
        return option[0].toUpperCase() + option.slice(1);
      }

      return option;
    }

    function getPreparedValues() {
      vm.preparedValues = vm.labels ? vm.labels : vm.values.map(vm.valuesMapping);
      return vm.preparedValues;
    }

    function optionClicked(value) {
      vm.onSelect && vm.onSelect({selectedOption: value});
      ngModel.$setViewValue(value);
      vm.isOpened = !vm.isOpened;

      if (vm.hasSearchInput()) {
        vm.mnSearch.value = '';
      }
    }

    function clickSearch(event) {
      event.stopPropagation();
    }

    function hasSearchInput() {
      return (vm.hasSearch && vm.values.length >= searchMinimumOptionsNumber) || false;
    }
  }
}
