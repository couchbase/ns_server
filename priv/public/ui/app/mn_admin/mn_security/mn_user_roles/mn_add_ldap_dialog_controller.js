(function () {
  "use strict";

  angular
    .module("mnUserRoles")
    .controller("mnAddLDAPDialogController", mnAddLDAPDialogController);

  function mnAddLDAPDialogController($scope, mnUserRolesService, mnPromiseHelper, $uibModalInstance) {
    var vm = this;

    vm.config = {
      connect: {
        hosts: "",
        port: "",
        encryption: "false",
        server_cert_validation: "false",
        cacert: "",
        query_dn: "",
        query_pass: ""
      },
      userDnMapping: "template",
      authentication: {
        authentication_enabled: false,
        user_dn_mapping: {
          template: ""
        }
      },
      cred: {},
      queryForGroups: "users_attrs",
      group: {
        authorization_enabled: false,
        nested_groups_enabled: false,
        groups_query: {},
      },
      groups_query_user: "",
      advanced: {
        request_timeout: 4000,
        max_parallel_connections: 1000,
        max_cache_size: 10000,
        cache_value_lifetime: 30000,
        nested_groups_max_depth: 10
      }
    };

    vm.save = save;
    vm.checkConnectivity = checkConnectivity;
    vm.checkAuthentication = checkAuthentication;
    vm.userDnMappingChanged = userDnMappingChanged;
    vm.queryForGroupsChanged = queryForGroupsChanged;
    vm.checkGroupsQuery = checkGroupsQuery;

    function userDnMappingChanged() {
      vm.config.authentication.user_dn_mapping = {};
    }

    function queryForGroupsChanged() {
      vm.config.group.groups_query = {scope: "one"};
    }

    function getUserDnMapping(config) {
      var userDnMapping = [{re: "(.+)"}];
      switch (vm.config.userDnMapping) {
      case "template":
        userDnMapping[0].template = config.user_dn_mapping.template || "";
        return JSON.stringify(userDnMapping);
      case "query":
        userDnMapping[0].query =
          (config.user_dn_mapping.base || "")+"??one?"+(config.user_dn_mapping.filter || "");
        return JSON.stringify(userDnMapping);
      case "custom":
        return config.user_dn_mapping.value || "";
      }
    }

    function getQueryForGroups(config) {
      switch (vm.config.queryForGroups) {
      case "users_attrs":
        return "%D?" + (config.groups_query.attributes || "") + "?one";
      case "query":
        return (config.groups_query.base || "") + "??" +
          (config.groups_query.scope || "") + "?" +
          (config.groups_query.filter || "");
      case "custom":
        return config.groups_query.value || "";
      }
    }

    function getConnectivitySettings() {
      var config = Object.assign({}, vm.config.connect);
      if (config.encryption == "false") {
        delete config.server_cert_validation;
      }
      if (config.server_cert_validation == "pasteCert") {
        config.server_cert_validation = "true";
      } else {
        delete config.cacert;
      }
      return config;
    }

    function getAuthenticationSettings() {
      var config = Object.assign({}, vm.config.authentication);
      if (config.authentication_enabled) {
        config.user_dn_mapping = getUserDnMapping(config);
      } else {
        delete config.user_dn_mapping;
      }
      return config;
    }

    function getQueryForGroupsSettings() {
      var config = Object.assign({}, vm.config.group);
      if (config.authorization_enabled) {
        config.groups_query = getQueryForGroups(config);
      } else {
        delete config.groups_query;
      }
      return config;
    }

    function maybeExtractResultFromError(resultName) {
      return function (error) {
        if (error.result) {
          vm[resultName] = {data: error};
          vm.errors = {};
        } else {
          vm.errors = error;
        }
      };
    }

    function checkConnectivity() {
      mnPromiseHelper(vm,
        mnUserRolesService.ldapSettingsValidate("connectivity", getConnectivitySettings()))
        .applyToScope("connectSuccessResult")
        .catchErrors(maybeExtractResultFromError("connectSuccessResult"));
    }

    function checkAuthentication() {
      var settings = Object.assign({}, getAuthenticationSettings(), vm.config.cred);
      mnPromiseHelper(vm,
        mnUserRolesService.ldapSettingsValidate("authentication", settings))
        .applyToScope("authenticationSuccessResult")
        .catchErrors(maybeExtractResultFromError("authenticationSuccessResult"));
    }

    function checkGroupsQuery() {
      var settings = Object.assign({groups_query_user: vm.config.groups_query_user},
                                   getQueryForGroupsSettings());
      mnPromiseHelper(vm,
        mnUserRolesService.ldapSettingsValidate("groups_query", settings))
        .applyToScope("queryForGroupsSuccessResult")
        .catchErrors(maybeExtractResultFromError("queryForGroupsSuccessResult"));
    }

    function save() {
      var config = Object.assign({}, getConnectivitySettings(),
                                 getAuthenticationSettings(),
                                 getQueryForGroupsSettings(),
                                 vm.config.advanced);

      mnPromiseHelper(vm, mnUserRolesService.postLdapSettings(config), $uibModalInstance)
        .showGlobalSpinner()
        .catchErrors()
        // .broadcast("reloadRolesPoller")
        .closeOnSuccess()
        .showGlobalSuccess("LDAP connected successfully!");
    }
  }
})();
