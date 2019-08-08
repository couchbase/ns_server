(function () {
  "use strict";

  angular
    .module("mnUserRolesService", ['mnHelper', 'mnPoolDefault'])
    .factory("mnUserRolesService", mnUserRolesFactory);

  function mnUserRolesFactory($q, $http, mnHelper, mnPoolDefault) {
    var mnUserRolesService = {
      getState: getState,
      addUser: addUser,
      deleteUser: deleteUser,
      getRoles: getRoles,
      getRolesByRole: getRolesByRole,
      getRolesTree: getRolesTree,
      getUsers: getUsers,
      getUser: getUser,
      getRoleUIID: getRoleUIID,

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

      reviewSelectedWrappers: reviewSelectedWrappers,
      getSaslauthdAuth: getSaslauthdAuth
    };

    var queryDnError = "LDAP DN should be supplied";
    var usersAttrsError = "The field can't be empty";

    return mnUserRolesService;

    function getSaslauthdAuth() {
      return $http({
        method: "GET",
        url: "/settings/saslauthdAuth"
      }).then(function (resp) {
        return resp.data;
      });
    }

    function clearLdapCache() {
      return $http({
        method: "POST",
        url: "/settings/invalidateLDAPCache"
      });
    }

    function reviewSelectedWrappers(selectedRoles, selectedGroupsRoles) {
      var rv = {};
      angular.forEach(
        Object.assign({}, selectedRoles, selectedGroupsRoles),
        function (value, key) {
          if ((typeof value == "object") ? Object.keys(value).length : value) {
            selectWrappers(key, true, rv);
          }
        });
      return rv;
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

    function getLdapSettings() {
      return $http({
        method: "GET",
        url: "/settings/ldap"
      });
    }

    function isAnonOrQueryDn(data, isAnon) {
      return (isAnon || data.query_dn);
    }

    function validateLDAPQuery(data) {
      return !!(data.user_dn_mapping &&
                data.user_dn_mapping.includes("query"));
    }

    function validateGroupQuery(data) {
      return !!(data.groups_query);
    }

    function validateGroupUserAttrs(formData) {
      return formData.queryForGroups === "users_attrs" &&
        !formData.group.groups_query.attributes;
    }

    function ldapConnectivityValidate(data, formData) {
      if (!isAnonOrQueryDn(data, formData.isAnon)) {
        return $q.reject({query_dn: queryDnError});
      }
      return $http.post("/settings/ldap/validate/connectivity", data);
    }

    function ldapAuthenticationValidate(data, formData) {
      if (!isAnonOrQueryDn(data, formData.isAnon) && validateLDAPQuery(data)) {
        return $q.reject({query_dn: queryDnError});
      }
      return $http.post("/settings/ldap/validate/authentication", data);
    }

    function ldapGroupsQueryValidate(data, formData) {
      var errors = {};
      if (!isAnonOrQueryDn(data, formData.isAnon) && validateGroupQuery(data)) {
        errors.query_dn = queryDnError;
      }
      if (validateGroupUserAttrs(formData)) {
        errors.groups_query = usersAttrsError;
      }
      if (!data.groups_query_user) {
        errors.groups_query_user = "The filed is mandatory";
      }
      if (Object.keys(errors).length) {
        return $q.reject(errors);
      } else {
        return $http.post("/settings/ldap/validate/groups_query", data);
      }
    }

    function postLdapSettings(data, formData) {
      var errors = {};
      var isGroups = data.authorization_enabled;
      var isUser = data.authentication_enabled;
      if (!isAnonOrQueryDn(data, formData.isAnon) && ((!isUser && !isGroups) ||
                                                      (validateLDAPQuery(data) && isUser) ||
                                                      (validateGroupQuery(data) && isGroups))) {
        errors.query_dn = queryDnError;
      }
      if (isGroups && validateGroupUserAttrs(formData)) {
        errors.groups_query = usersAttrsError;
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

    function putUserProfile(data) {
      return $http.put("/settings/rbac/profiles/@self", JSON.stringify(data));
    }

    function getUserProfile() {
      return $http.get("/settings/rbac/profiles/@self").then(function (resp) {
        if (!resp.data || !resp.data.scenarios) {
          resp.data = resp.data || {};
          resp.data.scenarios = presetScenario();
          return putUserProfile(resp.data).then(getUserProfile);
        } else {
          return resp.data;
        }
      }, function (resp) {
        switch (resp.status) {
        case "404":
        default: return putUserProfile({scenarios: presetScenario()}).then(getUserProfile);
        }
      });
    }

    function getRoles() {
      return $http({
        method: "GET",
        url: "/settings/rbac/roles"
      }).then(function (resp) {
        return resp.data;
      });
    }

    function getWrapperName(name) {
      switch (name) {
      case "data": return "Data Service";
      case "views": return "Views";
      case "query": return "Query and Index Services";
      case "fts": return "Search Service";
      case "analytics": return "Analytics Service";
      case "replication":
      case "bucket": return undefined;
      default: return name;
      }
    }

    function sortAdminAndGlobalRoles(roles) {
      var rv = new Array(8);

      roles.forEach(function (role) {
        switch (role.role) {
        case "admin": rv[0] = role; break;
        case "cluster_admin": rv[1] = role; break;
        case "security_admin": rv[2] = role; break;
        case "ro_admin": rv[3] = role; break;
        case "replication_admin": rv[4] = role; break;
        case "query_external_access": rv[5] = role; break;
        case "query_system_catalog": rv[6] = role; break;
        case "analytics_reader": rv[7] = role; break;
        default: rv.push(role); break;
        }
      });

      rv = _.compact(rv);

      return rv;
    }

    function sortBucketRoles(roles) {
      var rv = [];
      var restRoles = new Array(5);

      _.forEach(_.groupBy(roles, function (role) {
        return role.role.split("_")[0];
      }), function (value, key) {
        switch(key) {
        case "data": restRoles[0] = [getWrapperName(key), value]; break;
        case "views": restRoles[1] = [getWrapperName(key), value]; break;
        case "query": restRoles[2] = [getWrapperName(key), value]; break;
        case "fts": restRoles[3] = [getWrapperName(key), value]; break;
        case "analytics": restRoles[4] = [getWrapperName(key), value]; break;
        case "bucket":
        case "replication": rv = rv.concat(value); break;
        default: restRoles[5].push([getWrapperName(key), value]); break;
        }
      });

      restRoles = _.compact(restRoles);

      return rv.concat(restRoles);
    }

    function prepareRootRoles(roles) {
      var rv = new Array(2);

      _.forEach(_.groupBy(roles, 'bucket_name'), function (value, key) {
        switch (key) {
        case "undefined":
          rv[0] = ["Administration & Global Roles", sortAdminAndGlobalRoles(value)]; break;
        case "*":
          rv[1] = ["All Buckets (*)", sortBucketRoles(value)]; break;
        default:
          rv.push([key, sortBucketRoles(value)]); break;
        }
      });

      rv = _.compact(rv);

      return rv;
    }

    function getRolesTree(roles) {
      return prepareRootRoles(roles);
    }

    function getRoleUIID(role, isWrapper) {
      var rv = "";
      var bucketWrapperName = getWrapperName(role.bucket_name || "undefined");
      var serviceWrapperName;
      if (role.bucket_name) {
        serviceWrapperName = getWrapperName(role.role.split("_")[0]);
      }
      rv += bucketWrapperName;
      if (serviceWrapperName) {
        rv += ("|" + serviceWrapperName);
      }
      if (!isWrapper) {
        rv += ("|" + (role.bucket_name ? (role.role + '[' + role.bucket_name + ']') : role.role));
      }
      return rv;
    }

    function getUser(user, params) {
      return $http({
        method: "GET",
        url: getUserUrl(user),
        params: params
      });
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

    function presetScenario() {
      return [{
        name: "Cluster Overview",
        desc: "Stats showing the general health of your cluster.",
        preset: true,
        id: mnHelper.generateID(),
        groups: [(function (groupId) {
          return {
            id: groupId,
            name: "Server Resources",
            preset: true,
            charts: [{
              stats: {"cpu_utilization_rate": "@system"},
              preset: true,
              size: "small",
              specificStat: true, // for single-stat chart
              group: groupId,
              id: mnHelper.generateID(),
            }, {
              stats: {"mem_actual_free": "@system"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID(),
            }, {
              stats: {"swap_used": "@system"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID(),
            }, {
              stats: {"rest_requests": "@system"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID(),
            }]
          }
        })(mnHelper.generateID()), // 2nd group starts here with the comma ////
        (function (groupId) {
          return {
            id: groupId,
            name: "Data Service Overview (per bucket)",
            preset: true,
            charts: [{
              stats: {"ops": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"mem_used": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"couch_docs_actual_disk_size": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"ep_resident_items_rate": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID())]
      }, // 2nd scenario starts here with the comma ///////////////////////////
      {
        name: "Data Service",
        desc: "Data Service stats per bucket.",
        preset: true,
        id: mnHelper.generateID(),
        groups: [(function (groupId) {
          return {
            id: groupId,
            name: "Memory",
            preset: true,
            charts: [{
              stats: {"mem_used": "@kv-", "ep_mem_low_wat": "@kv-", "ep_mem_high_wat": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false, // false for multi-stat chart
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"ep_kv_size": "@kv-", "ep_meta_data_memory": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID()),
        (function (groupId) {
          return {
            id: groupId,
            name: "Ops",
            preset: true,
            charts: [{
              stats: {"ops": "@kv-","ep_cache_miss_rate": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"cmd_get": "@kv-", "cmd_set": "@kv-", "delete_hits": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID()),
        (function (groupId) {
          return {
            id: groupId,
            name: "Disk",
            preset: true,
            charts: [{
              stats: {"couch_docs_actual_disk_size": "@kv-", "couch_docs_data_size": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"disk_write_queue": "@kv-", "ep_data_read_failed": "@kv-", "ep_data_write_failed": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID()),
        (function (groupId) {
          return {
            id: groupId,
            name: "vBuckets",
            preset: true,
            charts: [{
              stats: {"ep_vb_total": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"vb_active_num": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"vb_pending_num": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"vb_replica_num": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID()),
        (function (groupId) {
          return {
            id: groupId,
            name: "DCP Queues",
            preset: true,
            charts: [{
              stats: {"ep_dcp_views+indexes_count": "@kv-", "ep_dcp_cbas_count": "@kv-", "ep_dcp_replica_count": "@kv-", "ep_dcp_xdcr_count": "@kv-", "ep_dcp_other_count": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"ep_dcp_views+indexes_producer_count": "@kv-", "ep_dcp_cbas_producer_count": "@kv-", "ep_dcp_replica_producer_count": "@kv-", "ep_dcp_xdcr_producer_count": "@kv-", "ep_dcp_other_producer_count": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"ep_dcp_views+indexes_items_remaining": "@kv-", "ep_dcp_cbas_items_remaining": "@kv-", "ep_dcp_replica_items_remaining": "@kv-", "ep_dcp_xdcr_items_remaining": "@kv-", "ep_dcp_other_items_remaining": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID())]
      }];
    }

  }
})();
