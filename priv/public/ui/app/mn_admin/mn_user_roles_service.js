import angular from "/ui/web_modules/angular.js";
import _ from "/ui/web_modules/lodash.js";

import mnPoolDefault from "/ui/app/components/mn_pool_default.js";
import mnStoreService from "/ui/app/components/mn_store_service.js";
import mnStatisticsNewService from "./mn_statistics_service.js";

export default "mnUserRolesService";

angular
  .module("mnUserRolesService", [mnPoolDefault, mnStoreService, mnStatisticsNewService])
  .factory("mnUserRolesService", mnUserRolesFactory);

function mnUserRolesFactory($q, $http, mnPoolDefault, mnStoreService, mnStatisticsNewService) {
  var mnUserRolesService = {
    getState: getState,
    addUser: addUser,
    deleteUser: deleteUser,
    getRoles: getRoles,
    getRolesByRole: getRolesByRole,
    getUsers: getUsers,
    getUser: getUser,
    lookupLDAPUser: lookupLDAPUser,

    addGroup: addGroup,
    deleteRolesGroup: deleteRolesGroup,
    getRolesGroups: getRolesGroups,
    getRolesGroup: getRolesGroup,
    putRolesGroup: putRolesGroup,
    getRolesGroupsState: getRolesGroupsState,

    ldapConnectivityValidate: ldapConnectivityValidate,
    ldapAuthenticationValidate: ldapAuthenticationValidate,
    ldapGroupsQueryValidate: ldapGroupsQueryValidate,

    postLdapSettings: postLdapSettings,
    getLdapSettings: getLdapSettings,
    clearLdapCache: clearLdapCache,

    getUserProfile: getUserProfile,
    putUserProfile: putUserProfile,

    saveDashboard: saveDashboard,
    getSaslauthdAuth: getSaslauthdAuth,
    packRolesToSend: packRolesToSend,
    getRoleParams: getRoleParams
  };

  var clientTLSCert = "Client Cert should be supplied";
  var queryDnError = "LDAP DN should be supplied";
  var usersAttrsError = "The field can't be empty";

  return mnUserRolesService;

  function getSaslauthdAuth() {
    return $http({
      method: "GET",
      url: "/settings/saslauthdAuth"
    }).then(function (resp) {
      return resp.data;
    }, function (resp) {
      return;
    });
  }

  function clearLdapCache() {
    return $http({
      method: "POST",
      url: "/settings/invalidateLDAPCache"
    });
  }

  function getLdapSettings() {
    return $http({
      method: "GET",
      url: "/settings/ldap"
    });
  }

  function validateLDAPQuery(data) {
    return !!(data.userDNMapping &&
              data.userDNMapping.includes("query"));
  }

  function validateGroupQuery(data) {
    return !!(data.groupsQuery);
  }

  function validateGroupUserAttrs(formData) {
    return formData.queryForGroups === "users_attrs" &&
      !formData.group.groupsQuery.attributes;
  }

  function validateAuthType(errors, data, formData) {
    if ((formData.authType == "creds") && !data.bindDN) {
      errors.bindDN = queryDnError;
    }
    if ((formData.authType == "cert") && !data.clientTLSCert) {
      errors.clientTLSCert = clientTLSCert;
    }
  }

  function ldapConnectivityValidate(data, formData) {
    var errors = {};
    validateAuthType(errors, data, formData);
    if (Object.keys(errors).length) {
      return $q.reject(errors);
    } else {
      return $http.post("/settings/ldap/validate/connectivity", data);
    }
  }

  function ldapAuthenticationValidate(data, formData) {
    var errors = {};
    if (validateLDAPQuery(data)) {
      validateAuthType(errors, data, formData);
    }
    if (Object.keys(errors).length) {
      return $q.reject(errors);
    } else {
      return $http.post("/settings/ldap/validate/authentication", data);
    }
  }

  function ldapGroupsQueryValidate(data, formData) {
    var errors = {};
    if (validateGroupQuery(data)) {
      validateAuthType(errors, data, formData);
    }
    if (validateGroupUserAttrs(formData)) {
      errors.groupsQuery = usersAttrsError;
    }
    if (!data.groupsQueryUser) {
      errors.groupsQueryUser = "The filed is mandatory";
    }
    if (Object.keys(errors).length) {
      return $q.reject(errors);
    } else {
      return $http.post("/settings/ldap/validate/groupsQuery", data);
    }
  }

  function getRoleParams(rolesByRole, role) {
    if (!rolesByRole || !rolesByRole[role.role]) {
      return;
    }
    return rolesByRole[role.role].params.map(param => role[param] || "*").join(":");
  }

  function packParams(params) {
    let i;
    let rv = [];
    params = params.split(":");
    for (i = 0; i < params.length; i++) {
      let val = params[i];
      if (val == "*") {
        if (i == 0) {
          rv.push("*");
        }
        break;
      } else {
        rv.push(val);
      }
    }
    return rv.join(":");
  }

  function packRolesToSend(selectedRoles, selectedRolesConfigs) {
    return Object
      .keys(selectedRoles)
      .filter(role => selectedRoles[role])
      .concat(Object
              .keys(selectedRolesConfigs)
              .reduce((acc, role) =>
                      acc.concat((selectedRolesConfigs[role] || [])
                                 .map(config => (role + "[" + packParams(config) + "]"))), []));
  }


  function postLdapSettings(data, formData) {
    var errors = {};
    var isGroups = data.authorizationEnabled;
    var isUser = data.authenticationEnabled;
    if ((!isUser && !isGroups) || (validateLDAPQuery(data) && isUser) ||
        (validateGroupQuery(data) && isGroups)) {
      validateAuthType(errors, data, formData);
    }
    if (isGroups && validateGroupUserAttrs(formData)) {
      errors.groupsQuery = usersAttrsError;
    }
    if (formData.connect.encryption !== "None" &&
        formData.connect.serverCertValidation == "pasteCert" &&
        formData.connect.cacert == "") {
      errors.cacert = "The certificate should be provided"
    }
    if (Object.keys(errors).length) {
      return $q.reject(errors);
    } else {
      return $http({
        method: "POST",
        url: "/settings/ldap",
        data: data
      });
    }
  }

  function saveDashboard() {
    return getProfile().then(function (resp) {
      var profile = resp.data;
      profile.scenarios = mnStoreService.store("scenarios").share();
      profile.groups = mnStoreService.store("groups").share();
      profile.charts = mnStoreService.store("charts").share();
      return putUserProfile(profile);
    });
  }

  function putUserProfile(data) {
    return $http.put("/settings/rbac/profiles/@self", JSON.stringify(data));
  }

  function getProfile() {
    return $http.get("/settings/rbac/profiles/@self").then(null, function (resp) {
      switch (resp.status) {
      case "404":
      default:
        resp.data = {};
        return resp;
      }
    });
  }

  function getUserProfile() {
    return $q.all([
      getProfile(),
      mnPoolDefault.get()
    ]).then(function (resp) {
      var profile = resp[0].data;
      var poolDefault = resp[1];

      if (profile.version) {
        //example of how to perform upgrade
        // if (profile.version < poolDefault.versions["70"]) {
        //   //add fields for 70
        //   profile.version = poolDefault.versions["70"];
        // }

        mnStoreService.createStore("scenarios", {keyPath: "id", fill: profile.scenarios});
        mnStoreService.createStore("groups", {keyPath: "id", fill: profile.groups});
        mnStoreService.createStore("charts", {keyPath: "id", fill: profile.charts});
        return profile;
      } else {
        //inititlize
        mnStoreService.createStore("scenarios", {keyPath: "id"});
        mnStoreService.createStore("groups", {keyPath: "id"});
        mnStoreService.createStore("charts", {keyPath: "id"});
        mnStatisticsNewService.doAddPresetScenario();
        return putUserProfile({
          version: poolDefault.versions["65"],
          scenarios: mnStoreService.store("scenarios").share(),
          groups: mnStoreService.store("groups").share(),
          charts: mnStoreService.store("charts").share()
        }).then(getUserProfile);
      }
    });
  }


  function getRoles() {
    return $http({
      method: "GET",
      url: "/_uiroles"
    }).then(function (resp) {
      let rv = resp.data;
      rv.rolesByRole = rv.folders.reduce((acc, group) => {
        group.roles.forEach(role => acc[role.role] = role);
        return acc;
      }, {});
      return rv;
    });
  }

  function getUser(user, params) {
    return $http({
      method: "GET",
      url: getUserUrl(user),
      params: params
    });
  }

  function lookupLDAPUser(user) {
    return $http({
      method: "GET",
      url: getLookupLDAPUserUrl(user)
    })
  }

  function getUsers(params) {
    var config = {
      method: "GET",
      url: "/settings/rbac/users"
    };

    config.params = {};
    if (params && params.permission) {
      config.params.permission = params.permission;
    }
    if (params && params.pageSize) {
      if (params.substr) {
        config.params.substr = params.substr;
      }
      config.params.pageSize = params.pageSize;
      config.params.startFromDomain = params.startFromDomain;
      config.params.startFrom = params.startFrom;
      config.params.order = params.order;
      config.params.sortBy = params.sortBy;
    }

    return $http(config);
  }

  function deleteUser(user) {
    return $http({
      method: "DELETE",
      url: getUserUrl(user)
    });
  }

  function deleteRolesGroup(group) {
    return $http({
      method: "DELETE",
      url: "/settings/rbac/groups/" + encodeURIComponent(group.id),
    });
  }

  function getUserUrl(user) {
    var base = "/settings/rbac/users/";
    return base + encodeURIComponent(user.domain) + "/"  + encodeURIComponent(user.id);
  }

  function getLookupLDAPUserUrl(user) {
    return "/settings/rbac/lookupLDAPUser/" + encodeURIComponent(user.id);
  }

  function getRolesByRole(userRoles) {
    return (userRoles ? $q.when(userRoles) : getRoles()).then(function (roles) {
      var rolesByRole = {};
      angular.forEach(roles, function (role) {
        rolesByRole[role.role + (role.bucket_name ? '[' + role.bucket_name + ']' : '')] = role;
      });
      return rolesByRole;
    });
  }

  function packData(user, roles, groups, isEditingMode, resetPassword) {
    var data = {
      roles: roles.indexOf("admin") > -1 ? "admin" : roles.join(','),
      name: user.name
    };

    if (mnPoolDefault.export.isEnterprise) {
      data.groups = groups.join(',');
    }

    if ((!isEditingMode && user.domain == "local") || resetPassword) {
      data.password = user.password;
    }

    return data;
  }

  function doAddUser(data, user) {
    return $http({
      method: "PUT",
      data: data,
      url: getUserUrl(user)
    });
  }

  function addGroup(group, roles, isEditingMode) {
    if (!group || !group.id) {
      return $q.reject({name: "name is required"});
    }
    if (isEditingMode) {
      return putRolesGroup(group, roles);
    } else {
      return getRolesGroup(group).then(function () {
        return $q.reject({name: "group already exists"});
      }, function () {
        return putRolesGroup(group, roles);
      });
    }
  }

  function getRolesGroups(params) {
    var config = {
      method: "GET",
      url: "/settings/rbac/groups",
      params: {}
    };

    if (params && params.pageSize) {
      if (params.substr) {
        config.params.substr = params.substr;
      }
      config.params.pageSize = params.pageSize;
      config.params.startFrom = params.startFrom;
      config.params.order = params.order;
      config.params.sortBy = params.sortBy;
    }

    return $http(config);
  }

  function getRolesGroup(group) {
    return $http({
      method: "GET",
      url: "/settings/rbac/groups/" + encodeURIComponent(group.id)
    });
  }

  function putRolesGroup(group, roles) {
    var config = {
      method: "PUT",
      url: "/settings/rbac/groups/" + encodeURIComponent(group.id),
      data: {
        roles: roles.indexOf("admin") > -1 ? "admin" : roles.join(','),
        description: group.description,
        ldap_group_ref: group.ldap_group_ref
      }
    };

    return $http(config);
  }

  function getRolesGroupsState(params) {
    return getRolesGroups(params).then(function (resp) {
      var i;
      for (i in resp.data.links) {
        resp.data.links[i] = resp.data.links[i].split("?")[1]
          .split("&")
          .reduce(function(prev, curr, i, arr) {
            var p = curr.split("=");
            prev[decodeURIComponent(p[0])] = decodeURIComponent(p[1]);
            return prev;
          }, {});
      }
      return resp.data;

    });
  }

  function addUser(user, roles, groups, isEditingMode, resetPassword) {
    if (!user || !user.id) {
      return $q.reject({username: "username is required"});
    }
    if (isEditingMode) {
      return doAddUser(packData(user, roles, groups, isEditingMode, resetPassword), user);
    } else {
      return getUser(user).then(function (users) {
        return $q.reject({username: "username already exists"});
      }, function () {
        return doAddUser(packData(user, roles, groups, isEditingMode), user);
      });
    }
  }

  function getState(params) {
    return getUsers(params).then(function (resp) {
      var i;
      for (i in resp.data.links) {
        resp.data.links[i] = resp.data.links[i].split("?")[1]
          .split("&")
          .reduce(function(prev, curr, i, arr) {
            var p = curr.split("=");
            prev[decodeURIComponent(p[0])] = decodeURIComponent(p[1]);
            return prev;
          }, {});
      }
      if (!resp.data.users) {//in oreder to support compatibility mode
        return {
          users: resp.data
        };
      } else {
        return resp.data;
      }
    });
  }
}
