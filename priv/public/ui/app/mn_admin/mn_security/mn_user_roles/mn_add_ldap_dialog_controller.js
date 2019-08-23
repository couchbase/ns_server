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
        encryption: "None",
        server_cert_validation: "false",
        cacert: "",
        query_dn: "",
        query_pass: ""
      },
      isAnon: false,
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
    vm.checkGroupsQuery = checkGroupsQuery;
    vm.clearLdapCache = clearLdapCache;
    vm.removeGroupsQueryErrors = removeGroupsQueryErrors;
    activate();

    function activate() {
      mnUserRolesService.getLdapSettings().then(function (resp) {
        var config = resp.data;
        vm.config.connect =
          unpackConnectivity(config);
        vm.config.userDnMapping =
          unpackUserDnMappingType(config.user_dn_mapping);
        vm.config.authentication.authentication_enabled =
          config.authentication_enabled;
        vm.config.authentication.user_dn_mapping =
          unpackUserDnMapping(vm.config.userDnMapping, config.user_dn_mapping);
        vm.config.queryForGroups =
          unpackQueryForGroupsType(config.groups_query);
        vm.config.group.authorization_enabled =
          config.authorization_enabled;
        vm.config.group.nested_groups_enabled =
          config.nested_groups_enabled;
        vm.config.group.groups_query =
          unpackQueryForGroups(vm.config.queryForGroups, config.groups_query);
        vm.config.advanced =
          unpackAdvancedSettings(config);
        vm.config.isAnon =
          isThisAnonConnection(config);
      });
    }

    function isThisAnonConnection(data) {
      return !data.query_dn && !!((data.authentication_enabled && data.user_dn_mapping &&
                                   data.user_dn_mapping.includes("query")) ||
                                  (data.authorization_enabled && data.groups_query));
    }

    function clearLdapCache() {
      delete vm.cacheCleared;
      return mnPromiseHelper(vm, mnUserRolesService.clearLdapCache(), $uibModalInstance)
        .broadcast("reloadRolesPoller")
        .applyToScope("cacheCleared");
    }

    function unpackAdvancedSettings(config) {
      return Object
        .keys(vm.config.advanced)
        .reduce(function (acc, key) {
          acc[key] = config[key];
          return acc;
        }, {});
    }

    function unpackConnectivity(config) {
      return Object
        .keys(vm.config.connect)
        .reduce(function (acc, key) {
          switch (key) {
          case "hosts": acc[key] = config[key].join(","); break;
          case "server_cert_validation":
            if (config[key] == false) {
              acc[key] = "false";
            } else if (config["cacert"]) {
              acc[key] = "pasteCert";
            } else {
              acc[key] = "true";
            }
            break;
          default:
            if (config[key] !== undefined) {
              acc[key] = config[key].toString();
            }
          }
          return acc;
        }, {});
    }

    function unpackUserDnMapping(type, mapping) {
      if (!mapping.length) {
        return {};
      }
      switch (type) {
      case "template":
        return {template: mapping[0].template.replace("{0}", "%u")};
      case "query":
        var query = mapping[0].query.split("?");
        return {base: query[0], filter: query[3].replace("{0}", "%u")};
      case "custom":
        return {value: JSON.stringify(mapping)};
      }
    }

    function unpackUserDnMappingType(userDnMapping) {
      if (userDnMapping.length > 0) {
        if (userDnMapping.length == 1) {
          if (userDnMapping[0].re == "(.+)") {
            if (userDnMapping[0].query) {
              return "query";
            }
          } else {
            return "custom";
          }
        } else {
          return "custom";
        }
      }
      return "template";
    }

    function unpackQueryForGroupsType(query) {
      if (!query || (query.includes("%D?") && query.includes("?base"))) {
        return "users_attrs";
      } else {
        return "query";
      }
    }

    function unpackQueryForGroups(type, groupsQuery) {
      if (!groupsQuery) {
        return {scope: "one"};
      }
      var query = groupsQuery.split("?");
      switch (type) {
      case "users_attrs":
        return {attributes: query[1], scope: "base"};
      case "query":
        return {base: query[0], scope: query[2] || "one", filter: query[3]};
      }
    }

    function getUserDnMapping(config) {
      var userDnMapping = [{re: "(.+)"}];
      switch (vm.config.userDnMapping) {
      case "template":
        userDnMapping[0].template = (config.user_dn_mapping.template  || "").replace("%u", "{0}");
        return JSON.stringify(userDnMapping);
      case "query":
        userDnMapping[0].query =
          (config.user_dn_mapping.base || "")+"??one?"
          +(config.user_dn_mapping.filter || "").replace("%u", "{0}");
        return JSON.stringify(userDnMapping);
      case "custom":
        return config.user_dn_mapping.value || "";
      }
    }

    function getQueryForGroups(config) {
      switch (vm.config.queryForGroups) {
      case "users_attrs":
        return "%D?" + (config.groups_query.attributes || "") + "?base";
      case "query":
        return (config.groups_query.base || "") + "??" +
          (config.groups_query.scope || "") + "?" +
          (config.groups_query.filter || "");
      }
    }

    function getConnectivitySettings() {
      var config = Object.assign({}, vm.config.connect);
      if (config.query_pass == "**********") {
        delete config.query_pass;
      }
      if (vm.config.isAnon) {
        config.query_dn = "";
        config.query_pass = "";
      }
      if (config.server_cert_validation == "pasteCert") {
        config.server_cert_validation = "true";
      } else if (config.server_cert_validation == "true") {
        config.cacert = "";
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

    function removeGroupsQueryErrors() {
      if (vm.errors) {
        delete vm.errors.groups_query;
      }
    }

    function removeErrors() {
      delete vm.errors;
      delete vm.connectSuccessResult;
      delete vm.authenticationSuccessResult;
      delete vm.queryForGroupsSuccessResult;
    }

    function checkConnectivity() {
      removeErrors();
      mnPromiseHelper(
        vm,
        mnUserRolesService.ldapConnectivityValidate(getConnectivitySettings(), vm.config))
        .applyToScope("connectSuccessResult")
        .catchErrors(maybeExtractResultFromError("connectSuccessResult"));
    }

    function checkAuthentication() {
      removeErrors();
      var settings = Object.assign({}, getConnectivitySettings(),
                                   getAuthenticationSettings(),
                                   vm.config.cred);
      mnPromiseHelper(vm,
                      mnUserRolesService.ldapAuthenticationValidate(settings, vm.config))
        .applyToScope("authenticationSuccessResult")
        .catchErrors(maybeExtractResultFromError("authenticationSuccessResult"));
    }

    function checkGroupsQuery() {
      removeErrors();
      var settings = Object.assign({groups_query_user: vm.config.groups_query_user},
                                   getConnectivitySettings(),
                                   getAuthenticationSettings(),
                                   getQueryForGroupsSettings());
      mnPromiseHelper(vm,
                      mnUserRolesService.ldapGroupsQueryValidate(settings, vm.config))
        .applyToScope("queryForGroupsSuccessResult")
        .catchErrors(maybeExtractResultFromError("queryForGroupsSuccessResult"));
    }

    function save() {
      removeErrors();
      var config = Object.assign({}, getConnectivitySettings(),
                                 getAuthenticationSettings(),
                                 getQueryForGroupsSettings(),
                                 vm.config.advanced);

      mnPromiseHelper(vm,
                      mnUserRolesService.postLdapSettings(config, vm.config),
                      $uibModalInstance)
        .showGlobalSpinner()
        .removeErrors()
        .catchErrors()
        .broadcast("reloadLdapSettings")
        .closeOnSuccess()
        .showGlobalSuccess("LDAP connected successfully!");
    }
  }
})();
