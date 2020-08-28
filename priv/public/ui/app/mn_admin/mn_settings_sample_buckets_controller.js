import angular from "/ui/web_modules/angular.js";
import _ from "/ui/web_modules/lodash.js";
import ngMessages from "/ui/web_modules/angular-messages.js";

import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";
import mnSettingsSampleBucketsService from "./mn_settings_sample_buckets_service.js";

export default "mnSettingsSampleBuckets";

angular
  .module("mnSettingsSampleBuckets", [
    mnPromiseHelper,
    mnElementCrane,
    mnSettingsSampleBucketsService,
    ngMessages
  ])
  .controller("mnSettingsSampleBucketsController", mnSettingsSampleBucketsController);

function mnSettingsSampleBucketsController($scope, mnSettingsSampleBucketsService, mnPromiseHelper) {
  var vm = this;
  vm.selected = {};
  vm.isCreateButtonDisabled = isCreateButtonDisabled;
  vm.installSampleBuckets = installSampleBuckets;
  vm.isAnyBucketSelected = isAnyBucketSelected;

  activate();
  function getState(selected) {
    return mnPromiseHelper(vm, mnSettingsSampleBucketsService.getSampleBucketsState(selected || vm.selected)).applyToScope("state");
  }
  function doGetState() {
    getState();
  }
  function activate() {
    getState().showSpinner();
    $scope.$watch("settingsSampleBucketsCtl.selected", function (value, oldValue) {
      if (value !== oldValue) {
        getState(value);
      }
    }, true);
    $scope.$on("reloadBucketStats", doGetState);
    $scope.$on("nodesChanged", doGetState);
    $scope.$on("reloadTasksPoller", doGetState);
  }


  function installSampleBuckets() {
    mnPromiseHelper(vm, mnSettingsSampleBucketsService.installSampleBuckets(vm.selected))
      .showGlobalSpinner()
      .catchGlobalErrors()
      .reloadState("app.admin.settings")
      .showGlobalSuccess("Task added successfully!");
  }

  function isAnyBucketSelected() {
    return _.keys(_.pick(vm.selected, _.identity)).length;
  }

  function isCreateButtonDisabled() {
    return vm.viewLoading || vm.state &&
      (_.chain(vm.state.warnings).values().some().value() ||
       !vm.state.available.length) ||
      !isAnyBucketSelected();
  }

}
