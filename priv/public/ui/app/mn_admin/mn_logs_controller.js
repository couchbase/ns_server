/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from "angular";

import mnPromiseHelper from "../components/mn_promise_helper.js";
import mnPoll from "../components/mn_poll.js";
import mnSpinner from "../components/directives/mn_spinner.js";
import mnMainSpinner from "../components/directives/mn_main_spinner.js";
import mnFilters from "../components/mn_filters.js";
import mnSearch from "../components/directives/mn_search/mn_search_directive.js";
import mnSortableTable from "../components/directives/mn_sortable_table.js";
import mnElementCrane from "../components/directives/mn_element_crane/mn_element_crane.js";
import mnSelectableNodesList from "../components/directives/mn_selectable_nodes_list.js";

import mnLogsService from "./mn_logs_service.js";
import mnLogRedactionService from "./mn_redaction_service.js";
import mnGroupsService from "./mn_groups_service.js";


export default 'mnLogs';

angular.module('mnLogs', [
  mnPromiseHelper,
  mnPoll,
  mnSpinner,
  mnMainSpinner,
  mnFilters,
  mnSearch,
  mnSortableTable,
  mnElementCrane,
  mnSelectableNodesList,
  mnLogsService,
  mnLogRedactionService,
  mnGroupsService
])
  .config(["$stateProvider", configure])
  .controller('mnLogsController', mnLogsController)

function configure($stateProvider) {
  $stateProvider
    .state('app.admin.logs', {
      url: '/logs',
      abstract: true,
      views: {
        "main@app.admin": {
          templateUrl: 'app/mn_admin/mn_logs.html',
          controller: 'mnLogsController as logsCtl'
        }
      },
      data: {
        title: "Logs",
        permissions: "cluster.logs.read"
      }
    });
}

function mnLogsController() {
}
