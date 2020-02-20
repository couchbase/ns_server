import angular from "/ui/web_modules/angular.js";
import uiSelect from "/ui/web_modules/ui-select.js";
import uiRouter from "/ui/web_modules/@uirouter/angularjs.js";
import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";
import uiCodemirror from "/ui/libs/angular-ui-codemirror.js";

import ngSanitize from "/ui/web_modules/angular-sanitize.js";
import ngMessages from "/ui/web_modules/angular-messages.js";

import mnCompaction from "/ui/app/components/mn_compaction.js";
import mnHelper from "/ui/app/components/mn_helper.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnPoll from "/ui/app/components/mn_poll.js";
import mnPoolDefault from "/ui/app/components/mn_pool_default.js";

import mnFilter from "/ui/app/components/directives/mn_filter/mn_filter.js";

import mnViewsListService from "./mn_views_list_service.js";
import mnViewsEditingService from "./mn_views_editing_service.js";
import mnViewsListController from  "./mn_views_list_controller.js";
import mnViewsEditingResultController from "./mn_views_editing_result_controller.js";
import mnViewsEditingController from "./mn_views_editing_controller.js";
import mnViewsDeleteViewDialogController from "./mn_views_delete_view_dialog_controller.js";
import mnViewsDeleteDdocDialogController from "./mn_views_delete_ddoc_dialog_controller.js";
import mnViewsCreateDialogController from "./mn_views_create_dialog_controller.js";
import mnViewsCopyDialogController from "./mn_views_copy_dialog_controller.js";

export default "mnViews";

angular
  .module("mnViews", [
    uiSelect,
    uiRouter,
    uiBootstrap,
    uiCodemirror,
    ngSanitize,
    ngMessages,
    mnCompaction,
    mnHelper,
    mnPromiseHelper,
    mnPoll,
    mnPoolDefault,
    mnViewsListService,
    mnViewsEditingService,
    mnFilter
  ])
  .controller("mnViewsController", mnViewsController)
  .controller("mnViewsListController", mnViewsListController)
  .controller("mnViewsEditingResultController", mnViewsEditingResultController)
  .controller("mnViewsEditingController", mnViewsEditingController)
  .controller("mnViewsDeleteViewDialogController", mnViewsDeleteViewDialogController)
  .controller("mnViewsDeleteDdocDialogController", mnViewsDeleteDdocDialogController)
  .controller("mnViewsCreateDialogController", mnViewsCreateDialogController)
  .controller("mnViewsCopyDialogController", mnViewsCopyDialogController);

function mnViewsController($state, mnPoolDefault) {
  var vm = this;
  vm.onSelectBucket = onSelectBucket;
  vm.mnPoolDefault = mnPoolDefault.latestValue();
  vm.ddocsLoading = true;
  vm.currentBucketName = $state.params.bucket;

  function onSelectBucket(selectedBucket) {
    $state.go('^.list', {bucket: selectedBucket});
  }
}
