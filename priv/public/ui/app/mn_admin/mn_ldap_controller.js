/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import angular from 'angular';
import uiBootstrap from 'angular-ui-bootstrap';
import uiRouter from '@uirouter/angularjs';

import mnUserRolesService from "./mn_user_roles_service.js";
import mnPromiseHelper from "../components/mn_promise_helper.js";
import mnPoolDefault from "../components/mn_pool_default.js";

export default "mnLDAP";

angular
  .module("mnLDAP", [mnUserRolesService, mnPromiseHelper, mnPoolDefault])
  .controller("mnLDAPController", ["$scope", "mnUserRolesService", "mnPromiseHelper", "mnPoolDefault", "mnHelper", mnLDAPController]);

function mnLDAPController($scope, mnUserRolesService, mnPromiseHelper, mnPoolDefault, mnHelper) {
  var vm = this;

  vm.config = {
    connect: {
      hosts: "",
      port: "",
      encryption: "None",
      serverCertValidation: "false",
      cacert: "",
      bindDN: "",
      bindPass: "",
      clientTLSCert: "",
      clientTLSKey: ""
    },
    authType: "anon",
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

  if (mnPoolDefault.export.compat.atLeast76) {
    vm.config.advanced.middleboxCompMode = false;
  }

  vm.isEnterprise = mnPoolDefault.export.isEnterprise;

  vm.advancedTemplatePlaceholder = `[
 {
  "match": "(.+)@(.+)\\\\.domain\\\\.net",
  "substitution": "cn={0},ou={1},dc=domain1,dc=com"
 },
 {
  "match": "(.+)@example\\\\.com",
  "ldapQuery": "ou=admins,dc=example,dc=com??one?(uid={0})"
 }
]`;
  vm.save = save;
  vm.checkConnectivity = checkConnectivity;
  vm.checkAuthentication = checkAuthentication;
  vm.checkGroupsQuery = checkGroupsQuery;
  vm.clearLdapCache = clearLdapCache;
  vm.removeGroupsQueryErrors = removeGroupsQueryErrors;
  vm.maybeDisableClientCert = maybeDisableClientCert;
  vm.mnPoolDefault = mnPoolDefault;
  vm.reloadState = mnHelper.reloadState;
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
      vm.config.authType =
        getAuthType(config);
      vm.config.connect.clientTLSCert = config.clientTLSCert || "";
      vm.config.connect.clientTLSKey = config.clientTLSKey || "";
      vm.isCertLoaded = !!config.clientTLSCert;
    });
    $scope.$watch("mnLDAPCtl.config.authentication.userDNMapping.advanced", validateUserDNMappingAdvanced)
  }

  function maybeSetUserDNMappingError(error) {
    vm.errors = vm.errors || {};
    vm.errors.userDNMapping = error;
  }

  function validateUserDNMappingAdvanced(v) {
    if (v) {
      try {
        JSON.parse(v);
        maybeSetUserDNMappingError("");
      } catch (e) {
        maybeSetUserDNMappingError(e);
      }
    } else {
      maybeSetUserDNMappingError("");
    }
  }

  function getAuthType(data) {
    return data.clientTLSCert ? "cert" : data.bindDN ? "creds" : "anon";
  }

  function clearLdapCache() {
    delete vm.cacheCleared;
    return mnPromiseHelper(vm, mnUserRolesService.clearLdapCache())
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

  function maybeDisableClientCert() {
    return vm.config.connect.encryption == 'None';
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
    if (mapping == "None") {
      return {template: "", scope: "one"}
    }
    switch (type) {
      case "template":
        return {template: mapping.template, scope: "one"};
      case "query":
        var query = mapping.query.split("?");
        return {base: query[0], scope: query[2] || "one", filter: query[3]};
      case "advanced":
        return {advanced: JSON.stringify(mapping.advanced, null, " ")};
    }
  }

  function unpackUserDnMappingType(userDnMapping) {
    if (userDnMapping == "None") {
      return "template";
    }
    if (userDnMapping.query) {
      return "query";
    }
    if (userDnMapping.advanced) {
      return "advanced";
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
    switch (vm.config.userDnMapping) {
      case "template":
        return JSON.stringify({template: config.userDNMapping.template || ""});
      case "query":
        var dnQuery =
          (config.userDNMapping.base || "") + "??" +
          (config.userDNMapping.scope || "") + "?" +
          (config.userDNMapping.filter || "");
        return JSON.stringify({query: dnQuery});
      case "advanced":
        try {
          return JSON.stringify({advanced: JSON.parse(config.userDNMapping.advanced) || ""});
        } catch (e) {
          return JSON.stringify({advanced: ""})
        }
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
    if (config.bindPass == "**********") {
      delete config.bindPass;
    }
    if (config.clientTLSKey == "**********") {
      delete config.clientTLSKey;
    }
    if (vm.config.authType != "creds") {
      config.bindDN = "";
      config.bindPass = "";
    }
    if (vm.config.authType != "cert") {
      config.clientTLSCert = "";
      config.clientTLSKey = "";
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

    if (!mnPoolDefault.export.compat.atLeast76) {
      delete vm.config.advanced.middleboxCompMode;
    }

    var config = Object.assign({}, getConnectivitySettings(),
                               getAuthenticationSettings(),
                               getQueryForGroupsSettings(),
                               vm.config.advanced);

    mnPromiseHelper(vm,mnUserRolesService.postLdapSettings(config, vm.config))
      .showGlobalSpinner()
      .catchErrors()
      .broadcast("reloadLdapSettings")
      .showGlobalSuccess("LDAP connected successfully!");
  }
}
