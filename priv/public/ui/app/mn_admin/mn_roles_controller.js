export default mnRolesController;

function mnRolesController(poolDefault, mnHelper, $uibModal, $q) {
  var vm = this;
  vm.addUser = addUser;
  vm.addRolesGroup = addRolesGroup;
  vm.addLDAP = addLDAP;

  function addUser() {
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_user_roles_add_dialog.html',
      controller: 'mnUserRolesAddDialogController as userRolesAddDialogCtl',
      resolve: {
        user: mnHelper.wrapInFunction(undefined),
        isSaslauthdAuthEnabled: function (mnUserRolesService) {
          return (poolDefault.saslauthdEnabled ?
                  mnUserRolesService.getSaslauthdAuth() : $q.when())
            .then((resp) => resp && resp.enabled);
        },
        isLdapEnabled: function (mnUserRolesService) {
          return ((poolDefault.isEnterprise && poolDefault.compat.atLeast65) ?
                  mnUserRolesService.getLdapSettings() : $q.when())
            .then((resp) =>
                  resp && resp.data.authenticationEnabled);
        }
      }
    });
  }

  function addLDAP() {
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_add_ldap_dialog.html',
      controller: 'mnAddLDAPDialogController as addLdapDialogCtl'
    });
  }

  function addRolesGroup() {
    $uibModal.open({
      templateUrl: 'app/mn_admin/mn_roles_groups_add_dialog.html',
      controller: 'mnRolesGroupsAddDialogController as rolesGroupsAddDialogCtl',
      resolve: {
        rolesGroup: mnHelper.wrapInFunction(undefined)
      }
    });
  }

}
