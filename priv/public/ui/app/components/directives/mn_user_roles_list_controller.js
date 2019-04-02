(function () {
  "use strict";

  angular
    .module('mnUserRolesList', [
      "mnFilters",
      "mnUserRolesService",
      "mnPromiseHelper"
    ])
    .directive('mnUserRolesList', mnUserRolesListDirective);

   function mnUserRolesListDirective() {
    var mnUserRolesList = {
      restrict: 'E',
      scope: {
        rolesToEnable: "=?",
        selectedRoles: "=",
        disabledGroupsRoles: "=?",
        selectedGroupsRoles: "=?"
      },
      templateUrl: 'app/components/directives/mn_user_roles_list.html',
      controller: mnUserRolesListController,
      controllerAs: "mnThisCtl",
      bindToController: true
    };

     return mnUserRolesList;

     function mnUserRolesListController(mnUserRolesService, mnPromiseHelper) {
       var vm = this;

       vm.openedWrappers = {};
       vm.containsSelected = {};

       vm.getUIID = mnUserRolesService.getRoleUIID;

       vm.toggleWrappers = toggleWrappers;
       vm.isRoleDisabled = isRoleDisabled;
       vm.onCheckChange = onCheckChange;

       activate();

       function activate() {
         vm.openedWrappers[vm.getUIID({role: "admin"}, true)] = true;

         mnPromiseHelper(vm, mnUserRolesService.getRoles())
           .showSpinner()
           .onSuccess(function (roles) {
             vm.allRoles = roles;
             vm.rolesTree = mnUserRolesService.getRolesTree(roles);
             if (vm.rolesToEnable) {
               // user.roles
               vm.rolesToEnable.forEach(function (role) {
                 var id = vm.getUIID(role);
                 vm.selectedRoles[id] = true;
                 onCheckChange(role, id);
               });
             }
           });
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
                 vm.selectedRoles[vm.getUIID(item)] = false;
               }
             });
           }
         }
         Object.assign(vm.selectedRoles, vm.selectedGroupsRoles);
         reviewSelectedWrappers();
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

       function reviewSelectedWrappers() {
         var containsSelected = {};
         _.forEach(vm.selectedRoles, function (value, key) {
           if (value) {
             selectWrappers(key, true, containsSelected);
           }
         });
         vm.containsSelected = containsSelected;
       }

       function isRoleDisabled(role) {
         return (role.role !== 'admin' && vm.selectedRoles[vm.getUIID({role: 'admin'})]) ||
           (role.bucket_name !== '*' &&
            vm.selectedRoles[vm.getUIID({role: role.role, bucket_name: '*'})]) ||
           (vm.disabledGroupsRoles && vm.disabledGroupsRoles[vm.getUIID(role)]);
       }

       function toggleWrappers(id, value) {
         vm.openedWrappers[id] = !vm.openedWrappers[id];
       }
     }
  }
})();
