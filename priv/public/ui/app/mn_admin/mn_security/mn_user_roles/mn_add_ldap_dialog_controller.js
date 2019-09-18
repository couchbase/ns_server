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
        serverCertValidation: "false",
        cacert: "",
        queryDN: "",
        queryPass: ""
      },
      isAnon: false,
      userDnMapping: "template",
      authentication: {
        authenticationEnabled: false,
        userDNMapping: {
          template: ""
        }
      },
      cred: {},
      queryForGroups: "users_attrs",
      group: {
        authorizationEnabled: false,
        nestedGroupsEnabled: false,
        groupsQuery: {},
      },
      groupsQueryUser: "",
      advanced: {
        requestTimeout: 4000,
        maxParallelConnections: 1000,
        maxCacheSize: 10000,
        cacheValueLifetime: 30000,
        nestedGroupsMaxDepth: 10
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
          unpackUserDnMappingType(config.userDNMapping);
        vm.config.authentication.authenticationEnabled =
          config.authenticationEnabled;
        vm.config.authentication.userDNMapping =
          unpackUserDnMapping(vm.config.userDnMapping, config.userDNMapping);
        vm.config.queryForGroups =
          unpackQueryForGroupsType(config.groupsQuery);
        vm.config.group.authorizationEnabled =
          config.authorizationEnabled;
        vm.config.group.nestedGroupsEnabled =
          config.nestedGroupsEnabled;
        vm.config.group.groupsQuery =
          unpackQueryForGroups(vm.config.queryForGroups, config.groupsQuery);
        vm.config.advanced =
          unpackAdvancedSettings(config);
        vm.config.isAnon =
          isThisAnonConnection(config);
      });
    }

    function isThisAnonConnection(data) {
      return !data.queryDN && !!((data.authenticationEnabled && data.userDNMapping &&
                                   data.userDNMapping.includes("query")) ||
                                  (data.authorizationEnabled && data.groupsQuery));
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
          case "serverCertValidation":
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
        userDnMapping[0].template = (config.userDNMapping.template  || "").replace("%u", "{0}");
        return JSON.stringify(userDnMapping);
      case "query":
        userDnMapping[0].query =
          (config.userDNMapping.base || "")+"??one?"
          +(config.userDNMapping.filter || "").replace("%u", "{0}");
        return JSON.stringify(userDnMapping);
      case "custom":
        return config.userDNMapping.value || "";
      }
    }

    function getQueryForGroups(config) {
      switch (vm.config.queryForGroups) {
      case "users_attrs":
        return "%D?" + (config.groupsQuery.attributes || "") + "?base";
      case "query":
        return (config.groupsQuery.base || "") + "??" +
          (config.groupsQuery.scope || "") + "?" +
          (config.groupsQuery.filter || "");
      }
    }

    function getConnectivitySettings() {
      var config = Object.assign({}, vm.config.connect);
      if (config.queryPass == "**********") {
        delete config.queryPass;
      }
      if (vm.config.isAnon) {
        config.queryDN = "";
        config.queryPass = "";
      }
      if (config.serverCertValidation == "pasteCert") {
        config.serverCertValidation = "true";
      } else if (config.serverCertValidation == "true") {
        config.cacert = "";
      } else {
        delete config.cacert;
      }
      return config;
    }

    function getAuthenticationSettings() {
      var config = Object.assign({}, vm.config.authentication);
      if (config.authenticationEnabled) {
        config.userDNMapping = getUserDnMapping(config);
      } else {
        delete config.userDNMapping;
      }
      return config;
    }

    function getQueryForGroupsSettings() {
      var config = Object.assign({}, vm.config.group);
      if (config.authorizationEnabled) {
        config.groupsQuery = getQueryForGroups(config);
      } else {
        delete config.groupsQuery;
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
        delete vm.errors.groupsQuery;
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
      var settings = Object.assign({groupsQueryUser: vm.config.groupsQueryUser},
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
