(function () {
  "use strict";

  angular
    .module("mnUserRoles")
    .controller("mnUserRolesAddDialogController", mnUserRolesAddDialogController);

  function mnUserRolesAddDialogController($scope, mnUserRolesService, $uibModalInstance, mnPromiseHelper, user, isLdapEnabled, mnPoolDefault, $timeout) {
    var vm = this;
    vm.user = _.clone(user) || {domain: mnPoolDefault.export.compat.atLeast50 ? "local" : "external"};
    vm.userID = vm.user.id || 'New';
    vm.save = save;
    vm.isEditingMode = !!user;
    vm.isLdapEnabled = isLdapEnabled;
    vm.onCheckChange = onCheckChange;
    vm.containsSelected = {};
    vm.openedWrappers = {};
    vm.selectedRoles = {};
    vm.getUIID = mnUserRolesService.getRoleUIID;
    vm.toggleWrappers = toggleWrappers;
    vm.focusError = false;
    vm.isRoleDisabled = isRoleDisabled;

    activate();

    function isRoleDisabled(role) {
      return (
        role.role !== 'admin' &&
          vm.selectedRoles[
            vm.getUIID({role: 'admin'})
          ]) || (
            role.bucket_name !== '*' &&
              vm.selectedRoles[
                vm.getUIID({role: role.role, bucket_name: '*'})
              ]);
    }

    function toggleWrappers(id, value) {
      vm.openedWrappers[id] = !vm.openedWrappers[id];
    }

    function selectWrappers(id, value, applyTo) {
      var wrappers = id.split("|");
      var flag = wrappers.pop();
      var id;
      while (wrappers.length) {
        id = wrappers.join("|");
        applyTo[id] = value;
        wrappers.pop();
      }
    }

    function getWrapperName(id) {
      var wrappers = id.split("|");
      wrappers.pop();
      return wrappers.join("|");
    }

    function reviewSelectedWrappers() {
      var containsSelected = {};
      _.forEach(vm.selectedRoles, function (value, key) {
        if (value) {
          selectWrappers(key, true, containsSelected);
        }
      });
      vm.containsSelected = containsSelected;
    }

    function onCheckChange(role, id) {
      var selectedRoles;
      if (vm.selectedRoles[id]) {
        if (role.role === "admin") {
          selectedRoles = {};
          selectedRoles[id] = true;
          vm.selectedRoles = selectedRoles;
        } else if (role.bucket_name === "*") {
          vm.allRoles.forEach(function (item) {
            if (item.bucket_name !== undefined &&
                item.bucket_name !== "*" &&
                item.role === role.role) {
              vm.selectedRoles[mnUserRolesService.getRoleUIID(item)] = false;
            }
          });
        }
      }
      reviewSelectedWrappers();
    }

    function activate() {
      vm.openedWrappers[vm.getUIID({role: "admin"}, true)] = true;

      mnPromiseHelper(vm, mnUserRolesService.getRoles())
        .showSpinner()
        .onSuccess(function (roles) {
          vm.allRoles = roles;
          vm.allRoleUIIDs = roles.map(function (role) {
            return mnUserRolesService.getRoleUIID(role);
          });
          vm.rolesTree = mnUserRolesService.getRolesTree(roles);
          if (user) {
            user.roles.forEach(function (role) {
              var id = mnUserRolesService.getRoleUIID(role);
              vm.selectedRoles[id] = true;
              onCheckChange(role, id);
            });
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

      mnPromiseHelper(vm, mnUserRolesService.addUser(vm.user, roles, vm.isEditingMode), $uibModalInstance)
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
