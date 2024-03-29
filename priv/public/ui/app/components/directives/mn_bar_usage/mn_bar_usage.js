/*
Copyright 2015-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from 'angular';
import _ from 'lodash';

import mnFilters from '../../mn_filters.js';
import template from "./mn_bar_usage.html";

export default 'mnBarUsage';

angular
  .module('mnBarUsage', [mnFilters])
  .directive('mnBarUsage', ["mnRescaleForSumFilter", mnBarUsageDirective]);

function mnBarUsageDirective(mnRescaleForSumFilter) {

  var mnBarUsage = {
    restrict: 'A',
    scope: {
      baseInfo: '=',
    },
    isolate: false,
    template,
    controller: ["$scope", controller]
  };

  return mnBarUsage;

  function controller($scope) {
    $scope.$watch('baseInfo', function (options) {
      if (!options) {
        return;
      }
      var sum = 0;
      var newOptions = _.cloneDeep(options);
      var items = newOptions.items;
      var values = _.map(items, function (item) {
        return Math.max(item.value, 0);
      });
      var total = _.chain(values).reduce(function (sum, num) {
        return sum + num;
      }).value();

      values = mnRescaleForSumFilter(100, values, total);

      _.each(values, function (item, i) {
        var v = values[i];
        values[i] += sum;
        newOptions.items[i].itemStyle = newOptions.items[i].itemStyle || {};
        newOptions.items[i].itemStyle.width = values[i] + "%";
        sum += v;
      });
      newOptions.tdItems = _.select(newOptions.items, function (item) {
        return item.name !== null;
      });

      $scope.config = newOptions;
    }, true);
  }
}
