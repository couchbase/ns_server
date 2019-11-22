import _ from "/ui/web_modules/lodash.js";

export default mnRolesGroupsAddDialogController;

function mnRolesGroupsAddDialogController(mnUserRolesService, $uibModalInstance, mnPromiseHelper, rolesGroup) {
  var vm = this;
  vm.rolesGroup = _.clone(rolesGroup) || {};
  vm.rolesGroupID = vm.rolesGroup.id || 'New';
  vm.save = save;
  vm.isEditingMode = !!rolesGroup;
  vm.selectedRoles = {};

  vm.focusError = false;

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

    mnPromiseHelper(vm, mnUserRolesService.addGroup(vm.rolesGroup, roles, vm.isEditingMode), $uibModalInstance)
      .showGlobalSpinner()
      .catchErrors()
      .broadcast("reloadRolesGroupsPoller")
      .closeOnSuccess()
      .showGlobalSuccess("Group saved successfully!");
  }
}
