/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from "angular";
import _ from "lodash";
import uiSelect from "ui-select";

import mnHelper from "../components/mn_helper.js";
import mnPromiseHelper from "../components/mn_promise_helper.js";
import mnPoll from "../components/mn_poll.js";
import mnSortableTable from "../components/directives/mn_sortable_table.js";
import mnSpinner from "../components/directives/mn_spinner.js";
import mnMainSpinner from "../components/directives/mn_main_spinner.js";
import mnEqual from "../components/directives/mn_validation/mn_equal.js";
import mnFilters from "../components/mn_filters.js";
import mnAutocompleteOff from "../components/directives/mn_autocomplete_off.js";
import mnFocus from "../components/directives/mn_focus.js";
import mnUserRolesSelect from "../components/directives/mn_user_roles_select_controller.js";
import mnFileReader from "../components/mn_file_reader.js";
import mnSearch from "../components/directives/mn_search/mn_search_directive.js";

import mnUserRolesService from "./mn_user_roles_service.js";
import mnUserRolesAddDialogController from "./mn_user_roles_add_dialog_controller.js";
import mnUserRolesDeleteDialogController from "./mn_user_roles_delete_dialog_controller.js";
import mnUserRolesLockDialogController from "./mn_user_roles_lock_dialog_controller.js";
import mnUserRolesUnlockDialogController from "./mn_user_roles_unlock_dialog_controller.js";
import mnUserRolesResetPasswordDialogController from "./mn_user_roles_reset_password_dialog_controller.js";

import mnRolesController from "./mn_roles_controller.js";
import mnUserRolesAddDialogTemplate from "./mn_user_roles_add_dialog.html";
import mnUserRolesResetPasswordDialogTemplate from "./mn_user_roles_reset_password_dialog.html";
import mnUserRolesDeleteDialogTemplate from "./mn_user_roles_delete_dialog.html";
import mnUserRolesLockDialogTemplate from "./mn_user_roles_lock_dialog.html";
import mnUserRolesUnlockDialogTemplate from "./mn_user_roles_unlock_dialog.html";

import mnTimezoneDetailsDowngradeModule from "../mn.timezone.details.downgrade.module.js";

export default "mnUserRoles";

angular
  .module("mnUserRoles", [
    uiSelect,
    mnHelper,
    mnPromiseHelper,
    mnPoll,
    mnSortableTable,
    mnSpinner,
    mnMainSpinner,
    mnEqual,
    mnFilters,
    mnAutocompleteOff,
    mnFocus,
    mnUserRolesService,
    mnUserRolesSelect,
    mnFileReader,
    mnSearch,
    mnTimezoneDetailsDowngradeModule
  ])
  .controller("mnUserRolesController", ["$scope", "$uibModal", "mnPromiseHelper", "mnUserRolesService", "mnPoller", "mnHelper", "$state", "poolDefault", "permissions", "mnTimezoneDetailsServiceDowngrade", mnUserRolesController])
  .controller("mnUserRolesDeleteDialogController", mnUserRolesDeleteDialogController)
  .controller("mnUserRolesLockDialogController", mnUserRolesLockDialogController)
  .controller("mnUserRolesUnlockDialogController", mnUserRolesUnlockDialogController)
  .controller("mnUserRolesResetPasswordDialogController", mnUserRolesResetPasswordDialogController)
  .controller("mnUserRolesAddDialogController", mnUserRolesAddDialogController)
  .controller("mnRolesController", mnRolesController);

function mnUserRolesController($scope, $uibModal, mnPromiseHelper, mnUserRolesService, mnPoller, mnHelper, $state, poolDefault, permissions, mnTimezoneDetailsServiceDowngrade) {
  var vm = this;

  vm.deleteUser = deleteUser;
  vm.lockUser = lockUser;
  vm.unlockUser = unlockUser;
  vm.editUser = editUser;
  vm.resetUserPassword = resetUserPassword;

  vm.filterField = "";

  vm.stateParams = $state.params;

  vm.pageSize = $state.params.pageSize;
  vm.pageSizeChanged = pageSizeChanged;
  vm.parseGroupNames = parseGroupNames;
  vm.sortByChanged = sortByChanged;
  vm.isOrderBy = isOrderBy;
  vm.isDesc = isDesc;
  vm.getRoleParams = getRoleParams;
  vm.localGMTOffset = mnTimezoneDetailsServiceDowngrade.getLocalGMTString();

  activate();

  function isOrderBy(sortBy) {
    return sortBy === $state.params.sortBy;
  }

  function isDesc() {
    return $state.params.order === "desc";
  }

  function pageSizeChanged() {
    $state.go('.', {
      pageSize: vm.pageSize
    });
  }

  function parseGroupNames(group) {
    return _.uniq(group.groups.concat(group.external_groups)).join(", ");
  }

  function sortByChanged(sortBy) {
    $state.go('.', {
      order: $state.params.sortBy != sortBy ? "asc" :
        $state.params.order === "asc" ? "desc" : "asc",
      sortBy: sortBy
    });
  }

  function getRoleParams(role) {
    return mnUserRolesService.getRoleParams(vm.rolesByRole, role);
  }

  function activate() {
    $scope.$watchGroup(["userRolesCtl.stateParams.order",
                        "userRolesCtl.stateParams.sortBy",
                        "userRolesCtl.stateParams.substr"], _.debounce(function () {
                          $scope.$broadcast("reloadRolesPoller");
                        }, 500, {leading: true}));

    $scope.$watch('userRolesCtl.filterField', _.debounce(function () {
      $state.go('.', {
        substr: vm.filterField || undefined
      })
    }, 500, {leading: true}), true);

    mnHelper.initializeDetailsHashObserver(vm, 'openedUsers', '.');

    mnUserRolesService.getRoles().then(roles => {
      vm.rolesByRole = roles.rolesByRole;
    });

    new mnPoller($scope, function () {
      return mnUserRolesService.getState($state.params);
    })
      .subscribe("state", vm)
      .setInterval(10000)
      .reloadOnScopeEvent("reloadRolesPoller")
      .cycle();
  }

  function editUser(user) {
    $uibModal.open({
      template: mnUserRolesAddDialogTemplate,
      controller: 'mnUserRolesAddDialogController as userRolesAddDialogCtl',
      resolve: {
        user: mnHelper.wrapInFunction(user),
        isSaslauthdAuthEnabled: mnHelper.wrapInFunction($scope.rolesCtl.isSaslauthdAuthEnabled),
        isLdapEnabled: mnHelper.wrapInFunction($scope.rolesCtl.isLdapEnabled),
        isSamlEnabled: mnHelper.wrapInFunction($scope.rolesCtl.isSamlEnabled),
        permissions: mnHelper.wrapInFunction(permissions)
      }
    });
  }
  function resetUserPassword(user) {
    $uibModal.open({
      template: mnUserRolesResetPasswordDialogTemplate,
      controller: 'mnUserRolesResetPasswordDialogController as userRolesResetPasswordDialogCtl',
      resolve: {
        user: mnHelper.wrapInFunction(user)
      }
    });
  }
  function lockUser(user) {
    $uibModal.open({
      template: mnUserRolesLockDialogTemplate,
      controller: 'mnUserRolesLockDialogController as userRolesLockDialogCtl',
      resolve: {
        user: mnHelper.wrapInFunction(user)
      }
    });
  }
  function unlockUser(user) {
    $uibModal.open({
      template: mnUserRolesUnlockDialogTemplate,
      controller: 'mnUserRolesUnlockDialogController as userRolesUnlockDialogCtl',
      resolve: {
        user: mnHelper.wrapInFunction(user)
      }
    });
  }

  function deleteUser(user) {
    $uibModal.open({
      template: mnUserRolesDeleteDialogTemplate,
      controller: 'mnUserRolesDeleteDialogController as userRolesDeleteDialogCtl',
      resolve: {
        user: mnHelper.wrapInFunction(user)
      }
    });
  }
}
