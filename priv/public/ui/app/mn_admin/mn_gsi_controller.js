import angular from "/ui/web_modules/angular.js";
import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";

import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnHelper from "/ui/app/components/mn_helper.js";
import mnFilters from "/ui/app/components/mn_filters.js";
import mnSpinner from "/ui/app/components/directives/mn_spinner.js";
import mnPoll from "/ui/app/components/mn_poll.js";
import mnPoolDefault from "/ui/app/components/mn_pool_default.js";
import mnAlertsService from "/ui/app/components/mn_alerts.js";
import mnPermissions from "/ui/app/components/mn_permissions.js";
import mnSearch from "/ui/app/components/directives/mn_search/mn_search_directive.js";
import mnSortableTable from "/ui/app/components/directives/mn_sortable_table.js";
import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";
import mnDetailStats from "/ui/app/components/directives/mn_detail_stats_controller.js";

import mnStatisticsNewService from "./mn_statistics_service.js";
import mnGsiService from "./mn_gsi_service.js";

import {mnGsiItemController, mnGsiItemStatsController, mnGsiItemDetails} from "./mn_gsi_item_details.js";
import mnFooterStatsController from "./mn_footer_stats_controller.js";
import mnGsiTableDirective from "./mn_gsi_table_directive.js";

export default 'mnGsi';

angular
  .module('mnGsi', [
    uiBootstrap,
    mnPromiseHelper,
    mnHelper,
    mnFilters,
    mnSpinner,
    mnPoll,
    mnPoolDefault,
    mnAlertsService,
    mnPermissions,
    mnSearch,
    mnSortableTable,
    mnElementCrane,
    mnDetailStats,
    mnGsiService,
    mnStatisticsNewService
  ])
  .config(configure)
  .controller('mnGsiController', mnGsiController)
  .controller('mnFooterStatsController', mnFooterStatsController)
  .controller('mnGsiItemController', mnGsiItemController)
  .controller('mnGsiItemStatsController', mnGsiItemStatsController)
  .directive('mnGsiItemDetails', mnGsiItemDetails)
  .directive('mnGsiTable', mnGsiTableDirective);

function configure($stateProvider) {

  $stateProvider
    .state('app.admin.gsi', {
      url: "/index?openedIndex",
      params: {
        openedIndex: {
          array: true,
          dynamic: true
        }
      },
      data: {
        title: "Indexes",
        permissions: "cluster.bucket['.'].n1ql.index.read"
      },
      views: {
        "main@app.admin": {
          controller: "mnGsiController as gsiCtl",
          templateUrl: "app/mn_admin/mn_gsi.html"
        }
      }
    });
}

function mnGsiController($scope, mnGsiService, mnPoller) {
  var vm = this;
  activate();

  function activate() {
    new mnPoller($scope, function () {
      return mnGsiService.getIndexesState();
    })
      .setInterval(10000)
      .subscribe("state", vm)
      .reloadOnScopeEvent("indexStatusURIChanged")
      .cycle();
  }
}
