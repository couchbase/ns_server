(function () {
  "use strict";

  angular
    .module("mnUserRoles")
    .controller("mnRolesController", mnRolesController);

  function mnRolesController(poolDefault, mnHelper, $uibModal) {
    var vm = this;
    vm.addUser = addUser;
    vm.addRolesGroup = addRolesGroup;
    vm.addLDAP = addLDAP;

    function addUser() {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_security/mn_user_roles/add_dialog/mn_user_roles_add_dialog.html',
        controller: 'mnUserRolesAddDialogController as userRolesAddDialogCtl',
        resolve: {
          user: mnHelper.wrapInFunction(undefined),
          isLdapEnabled: mnHelper.wrapInFunction(poolDefault.saslauthdEnabled)
        }
      });
    }

    function addLDAP() {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_security/mn_user_roles/mn_add_ldap_dialog.html',
        controller: 'mnAddLDAPDialogController as addLdapDialogCtl'
      });
    }

    function addRolesGroup() {
      $uibModal.open({
        templateUrl: 'app/mn_admin/mn_security/mn_roles_groups_add_dialog.html',
        controller: 'mnRolesGroupsAddDialogController as rolesGroupsAddDialogCtl',
        resolve: {
          rolesGroup: mnHelper.wrapInFunction(undefined),
          isLdapEnabled: mnHelper.wrapInFunction(poolDefault.saslauthdEnabled)
        }
      });
    }

  }
})();
