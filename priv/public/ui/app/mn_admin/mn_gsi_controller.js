import angular from "/ui/web_modules/angular.js";
import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";
import {format} from "/ui/web_modules/d3-format.js";
import _ from "/ui/web_modules/lodash.js";

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
import mnFooterStatsController from "./mn_gsi_footer_controller.js";
import mnGsiTableDirective from "./mn_gsi_table_directive.js";
import mnKeyspaceSelector from "/ui/app/mn.keyspace.selector.downgrade.module.js"
import {Subject} from "/ui/web_modules/rxjs.js";
import {takeUntil, filter, withLatestFrom} from "/ui/web_modules/rxjs/operators.js";
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
    mnStatisticsNewService,
    mnKeyspaceSelector
  ])
  .config(configure)
  .controller('mnGsiController', mnGsiController)
  .controller('mnGsiFooterController', mnFooterStatsController)
  .controller('mnGsiItemController', mnGsiItemController)
  .controller('mnGsiItemStatsController', mnGsiItemStatsController)
  .directive('mnGsiItemDetails', mnGsiItemDetails)
  .directive('mnGsiTable', mnGsiTableDirective);

function configure($stateProvider) {
  $stateProvider
    .state('app.admin.gsi', {
      url: "/index?indexesBucket&indexesScope&openedIndex&perIndexPage&perNodePage&indexesView",
      params: {
        openedIndex: {
          array: true,
          dynamic: true
        },
        indexesView: {
          value: 'viewByIndex',
          dynamic: true
        },
        indexesBucket: {
          value: "",
          dynamic: true
        },
        indexesScope: {
          value: "_default",
          dynamic: true
        },
        footerBucket: {
          value: null,
          dynamic: true
        },
        perNodePage: {
          value: {},
          type: "json",
          dynamic: true
        },
        perIndexPage: {
          value: {page:1, size:10},
          type: "json",
          dynamic: true
        },
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
      },
      redirectTo: function (trans) {
        var mnPermissionsService = trans.injector().get("mnPermissions");
        var params = _.clone(trans.params(), true);
        return mnPermissionsService.check().then(function (permissions) {
          var indexesRead = permissions.bucketNames['.n1ql.index!read'];
          var state = {state: "app.admin.gsi", params: params};
          if (!params.indexesBucket && indexesRead && indexesRead[0]) {
            state.params.indexesBucket = indexesRead[0];
            return state;
          }
        });
      }
    });
}
function mnGsiController($scope, mnGsiService, mnPoller, $state, mnCollectionsService,
                         poolDefault) {
  var vm = this;

  vm.setIndexesView = setIndexesView;

  activate();

  function setIndexesView() {
    $state.go('.', {indexesView: vm.viewBy}).then(() => vm.poller.reload());
  }

  function activate() {
    vm.viewBy = $state.params.indexesView;

    let mnOnDestroy = new Subject();

    vm.poller =
      new mnPoller($scope, () => {
        if (poolDefault.compat.atLeast70) {
          let params = vm.mnCollectionSelectorService.stream.result.getValue();
          if ($state.params.indexesView == "viewByNode") {
            return mnGsiService.getIndexesStateByNodes(params);
          } else {
            return mnGsiService.getIndexesState(params);
          }
        } else {
          if ($state.params.indexesView == "viewByNode") {
            return mnGsiService.getIndexesStateByNodesMixed();
          } else {
            return mnGsiService.getIndexesStateMixed();
          }
        }
      })
      .setInterval(10000)
      .subscribe("state", vm)
      .reloadOnScopeEvent("indexStatusURIChanged");

    if (!poolDefault.compat.atLeast70) {
      vm.poller.reload();
      return;
    }

    vm.mnCollectionSelectorService =
      mnCollectionsService.createCollectionSelector({
        component: {mnOnDestroy},
        steps: ["bucket", "scope"]
      });

    vm.mnCollectionSelectorService.stream.showHideDropdown
      .pipe(filter(v => !v),
            takeUntil(mnOnDestroy))
      .subscribe(stateGo);

    $scope.$on("$destroy", function () {
      mnOnDestroy.next();
      mnOnDestroy.complete();
    });

    $scope.$watchCollection(() => ({
      bucket: $state.params.indexesBucket,
      scope: $state.params.indexesScope
    }), v => {
      vm.mnCollectionSelectorService.setKeyspace(v);
    });

    function stateGo() {
      vm.poller.reload();
      let params = vm.mnCollectionSelectorService.stream.result.getValue();
      $state.go('.', {
        indexesBucket: params.bucket ? params.bucket.name: null,
        indexesScope: params.scope ? params.scope.name : null
      }, {notify: false});
    }
  }

}
