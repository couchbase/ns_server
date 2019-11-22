import angular from "/ui/web_modules/angular.js";

import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnPoll from "/ui/app/components/mn_poll.js";
import mnSpinner from "/ui/app/components/directives/mn_spinner.js";
import mnFilters from "/ui/app/components/mn_filters.js";
import mnSearch from "/ui/app/components/directives/mn_search/mn_search_directive.js";
import mnSortableTable from "/ui/app/components/directives/mn_sortable_table.js";
import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";
import mnSelectableNodesList from "/ui/app/components/directives/mn_selectable_nodes_list.js";

import mnLogsService from "./mn_logs_service.js";
import mnLogRedactionService from "./mn_redaction_service.js";
import mnGroupsService from "./mn_groups_service.js";
import mnLogsCollectInfoController from "./mn_logs_collect_info_controller.js";
import {mnLogsListController, moduleCodeFilter} from "./mn_logs_list_controller.js";

export default 'mnLogs';

angular.module('mnLogs', [
  mnPromiseHelper,
  mnPoll,
  mnSpinner,
  mnFilters,
  mnSearch,
  mnSortableTable,
  mnElementCrane,
  mnSelectableNodesList,
  mnLogsService,
  mnLogRedactionService,
  mnGroupsService
])
  .controller('mnLogsController', mnLogsController)
  .controller('mnLogsListController', mnLogsListController)
  .controller('mnLogsCollectInfoController', mnLogsCollectInfoController)
  .filter('moduleCode', moduleCodeFilter);

function mnLogsController($scope, mnHelper, mnLogsService) {
  var vm = this;
}
