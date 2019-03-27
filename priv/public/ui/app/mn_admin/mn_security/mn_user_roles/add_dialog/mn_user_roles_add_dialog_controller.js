(function () {
  "use strict";

  angular
    .module("mnUserRoles")
    .controller("mnUserRolesAddDialogController", mnUserRolesAddDialogController);

  function mnUserRolesAddDialogController($scope, mnUserRolesService, $uibModalInstance, mnPromiseHelper, user, isLdapEnabled, mnPoolDefault, $timeout, mnHelper, $q) {
    var vm = this;
    vm.user = _.clone(user) || {domain: mnPoolDefault.export.compat.atLeast50 ? "local" : "external"};
    vm.userID = vm.user.id || 'New';
    vm.save = save;
    vm.isEditingMode = !!user;
    vm.isLdapEnabled = isLdapEnabled;
    vm.selectedRoles = {};
    vm.selectedGroups = {};

    vm.focusError = false;
    vm.getGroupTitle = getGroupTitle;
    vm.selectedPanel = "roles";

    activate();

    function getGroupTitle(roles) {
      return roles && roles.map(function (v) {
        return vm.byRole[v.role + (v.bucket_name ? '[' + v.bucket_name + ']' : '')].name;
      }).join(',');
    }

    function activate() {
      $q.all([
        mnUserRolesService.getRolesByRole(),
        mnUserRolesService.getRolesGroups()
      ]).then(function (groups) {
        vm.byRole = groups[0];
        vm.groups = groups[1].data;
        if (vm.user.groups) {
          vm.selectedGroups = vm.user.groups.reduce(function (acc, group) {
            acc[group] = true;
            return acc;
          }, {});
        }
      });
    }

    function save() {
      if (vm.form.$invalid) {
        vm.focusError = true;
        return;
      }

      //example of the inсoming role
      //All Buckets (*)|Query and Index Services|query_insert[*]
      var roles = [];
      _.forEach(vm.selectedRoles, function (value, key) {
        if (value) {
          var path = key.split("|");
          roles.push(path[path.length - 1]);
        }
      });



      mnPromiseHelper(vm, mnUserRolesService.addUser(
        vm.user, roles, mnHelper.checkboxesToList(vm.selectedGroups), vm.isEditingMode,
      ), $uibModalInstance)
        .showGlobalSpinner()
        .catchErrors(function (errors) {
          vm.focusError = !!errors;
          vm.errors = errors;
        })
        .broadcast("reloadRolesPoller")
        .closeOnSuccess()
        .showGlobalSuccess("User saved successfully!");
    }
  }
})();
