(function () {
  "use strict";

  angular
    .module("mnUserRolesService", ['mnHelper'])
    .factory("mnUserRolesService", mnUserRolesFactory);

  function mnUserRolesFactory($q, $http, mnHelper, mnPoolDefault) {
    var mnUserRolesService = {
      getState: getState,
      addUser: addUser,
      getRoles: getRoles,
      deleteUser: deleteUser,
      getRolesByRole: getRolesByRole,
      getRolesTree: getRolesTree,
      getUsers: getUsers,
      getRoleUIID: getRoleUIID
    };

    return mnUserRolesService;

    function getRoles() {
      return $http({
        method: "GET",
        url: "/settings/rbac/roles"
      }).then(function (resp) {
        return resp.data;
      });
    }

    function sort(array) {
      if (angular.isArray(array) && angular.isArray(array[0])) {
        array.forEach(sort);
        array.sort(function(a, b) {
          var aHasTitle = angular.isArray(a[1]) || !!a[0].bucket_name;
          var bHasTitle = angular.isArray(b[1]) || !!b[0].bucket_name;
          if (!aHasTitle && bHasTitle) {
            return -1;
          }
          if (aHasTitle && !bHasTitle) {
            return 1;
          }
          return 0;
        });
      }
    }

    function getWrapperName(name) {
      switch (name) {
      case "data": return "Data Service";
      case "views": return "Views";
      case "query": return "Query and Index Services";
      case "fts": return "Search Service";
      case "analytics": return "Analytics Service";
      case "undefined": return "Administrator Roles";
      case "*": return "All Buckets (*)";
      case "replication":
      case "bucket": return undefined;
      default: return name;
      }
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

    function getRolesTree(roles) {
      roles = _.sortBy(roles, "name");
      var roles1 = _.groupBy(roles, 'bucket_name');
      var rv = [];

      rv.push([getWrapperName("undefined"), roles1["undefined"]]);

      _.forEach(roles1, function (array, bucketName) {
        if (bucketName == "undefined") {
          return;
        }

        var byRole = _.groupBy(array, function (role) {
          return role.role.split("_")[0];
        });

        var thisBucketRoles = byRole.bucket.concat(byRole.replication);

        (["data", "views", "query", "fts", "analytics"]).forEach(function (service) {
          thisBucketRoles.push([getWrapperName(service), byRole[service]]);
        });

        rv.push([getWrapperName(bucketName), thisBucketRoles]);
      });

      return rv;
    }

    function getUser(user) {
      return $http({
        method: "GET",
        url: getUserUrl(user)
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
        config.params.pageSize = params.pageSize;
        config.params.startFromDomain = params.startFromDomain;
        config.params.startFrom = params.startFrom;
      }

      return $http(config);
    }

    function deleteUser(user) {
      return $http({
        method: "DELETE",
        url: getUserUrl(user)
      });
    }

    function getUserUrl(user) {
      var base = "/settings/rbac/users/";
      if (mnPoolDefault.export.compat.atLeast50) {
        return base + encodeURIComponent(user.domain) + "/"  + encodeURIComponent(user.id);
      } else {
        return base + encodeURIComponent(user.id);
      }
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

    function packData(user, roles, isEditingMode, resetPassword) {
      var data = {
        roles: roles.indexOf("admin") > -1 ? "admin" : roles.join(','),
        name: user.name
      };

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

    function addUser(user, roles, isEditingMode, resetPassword) {
      if (!user || !user.id) {
        return $q.reject({username: "username is required"});
      }
      if (!resetPassword && (!roles || !roles.length)) {
        return $q.reject({roles: "at least one role should be added"});
      }
      if (isEditingMode) {
        return doAddUser(packData(user, roles, isEditingMode, resetPassword), user);
      } else {
        return getUser(user).then(function (users) {
          return $q.reject({username: "username already exists"});
        }, function () {
          return doAddUser(packData(user, roles, isEditingMode), user);
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
})();
