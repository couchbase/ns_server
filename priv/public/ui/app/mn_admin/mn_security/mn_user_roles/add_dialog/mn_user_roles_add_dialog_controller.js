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
    vm.closedWrappers = {};
    vm.selectedRoles = {};
    vm.getUIID = mnUserRolesService.getRoleUIID;
    vm.toggleWrappers = toggleWrappers;
    vm.focusError = false;
    vm.show = show;

    activate();

    function show(a) {
      console.log(a)
    }

    function toggleWrappers(id, value) {
      vm.closedWrappers[id] = (value !== undefined) ? value : !vm.closedWrappers[id];
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

    function onCheckChange(role, id) {
      var selectedRoles;
      var containsSelected;
      if (role.role === "admin") {
        selectedRoles = {};
        containsSelected = {};
        if (vm.selectedRoles[id]) {
          vm.allRoles.forEach(function (roleID) {
            selectedRoles[roleID] = true;
            selectWrappers(roleID, true, containsSelected);
          });
        }
        vm.selectedRoles = selectedRoles;
        vm.containsSelected = containsSelected;
      } else {
        if (vm.selectedRoles[id]) {
          selectWrappers(id, true, vm.containsSelected);
        } else {
          containsSelected = {};
          _.forEach(vm.selectedRoles, function (value, key) {
            if (value) {
              selectWrappers(key, true, containsSelected);
            }
          });
          vm.containsSelected = containsSelected;
        }
      }
    }

    function activate() {
      mnPromiseHelper(vm, mnUserRolesService.getRoles())
        .showSpinner()
        .onSuccess(function (roles) {
          vm.allRoles = roles.map(function (role) {
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
