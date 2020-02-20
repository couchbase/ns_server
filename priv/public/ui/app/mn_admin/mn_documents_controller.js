import angular from "/ui/web_modules/angular.js";
import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";
import uiRouter from "/ui/web_modules/@uirouter/angularjs.js";
import uiCodemirror from "/ui/libs/angular-ui-codemirror.js";

import mnDocumentsControlController from "./mn_documents_control_controller.js";
import mnDocumentsListController from "./mn_documents_list_controller.js";
import mnDocumentsCreateDialogController from "./mn_documents_create_dialog_controller.js";
import mnDocumentsEditingController from "./mn_documents_editing_controller.js";
import mnDocumentsDeleteDialogController from "./mn_documents_delete_dialog_controller.js";

import mnDocumentsListService from "./mn_documents_list_service.js";
import mnDocumentsEditingService from "./mn_documents_editing_service.js";

import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnFilters from "/ui/app/components/mn_filters.js";
import mnFilter from "/ui/app/components/directives/mn_filter/mn_filter.js";
import mnSpinner from "/ui/app/components/directives/mn_spinner.js";
import ngMessages from "/ui/web_modules/angular-messages.js";

import mnPoll from "/ui/app/components/mn_poll.js";
import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";

export default "mnDocuments";

angular
  .module("mnDocuments", [
    mnDocumentsListService,
    mnDocumentsEditingService,
    mnPromiseHelper,
    mnFilter,
    mnFilters,
    uiRouter,
    uiBootstrap,
    uiCodemirror,
    mnSpinner,
    ngMessages,
    mnPoll,
    mnElementCrane
  ])
  .controller("mnDocumentsController", mnDocumentsController)
  .controller("mnDocumentsControlController", mnDocumentsControlController)
  .controller("mnDocumentsCreateDialogController", mnDocumentsCreateDialogController)
  .controller("mnDocumentsListController", mnDocumentsListController)
  .controller("mnDocumentsEditingController", mnDocumentsEditingController)
  .controller("mnDocumentsDeleteDialogController", mnDocumentsDeleteDialogController);

function mnDocumentsController($state) {
  var vm = this;

  vm.onSelectBucketName = onSelectBucketName;
  vm.currentBucketName = $state.params.bucket;

  function onSelectBucketName(selectedBucket) {
    $state.go('^.list', {
      bucket: selectedBucket,
      pageNumber: 0
    });
  }
}
