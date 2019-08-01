(function () {
  "use strict";

  angular.module('mnSecurity', [
    'mnUserRoles',
    'mnPluggableUiRegistry',
    'mnRootCertificate',
    'mnElementCrane',
    'mnClientCertificate',
    'mnRedaction',
    'mnRolesGroups'
  ]).config(mnIndexesConfig);

  function mnIndexesConfig($stateProvider) {
    $stateProvider
      .state('app.admin.security', {
        url: "/security",
        views: {
          "main@app.admin": {
            controller: "mnSecurityController as securityCtl",
            templateUrl: "app/mn_admin/mn_security/mn_security.html"
          }
        },
        data: {
          permissions: "cluster.admin.security.read",
          title: "Security"
        },
        redirectTo: function (trans) {
          var mnPoolDefault = trans.injector().get("mnPoolDefault");
          var isEnterprise = trans.injector().get("mnPools").export.isEnterprise;
          var ldapEnabled = mnPoolDefault.export.saslauthdEnabled;
          var atLeast50 = mnPoolDefault.export.compat.atLeast50;
          var atLeast45 = mnPoolDefault.export.compat.atLeast45;

          if (atLeast50) {
            return {state: "app.admin.security.roles.user"};
          } else {
            if (isEnterprise && ldapEnabled && atLeast45) {
              return {state: "app.admin.security.externalRoles"};
            } else {
              return {state: "app.admin.security.internalRoles"};
            }
          }
        }
      })
      .state('app.admin.security.externalRoles', {
        url: "/externalRoles?openedUsers",
        controller: "mnUserRolesController as userRolesCtl",
        templateUrl: "app/mn_admin/mn_security/mn_user_roles/mn_user_roles.html",
        params: {
          openedUsers: {
            array: true,
            dynamic: true
          }
        },
        data: {
          compat: "atLeast45 && !atLeast50",
          ldap: true,
          enterprise: true
        }
      })
      .state('app.admin.security.roles', {
        abstract: true,
        templateUrl: "app/mn_admin/mn_security/mn_roles.html",
        controller: "mnRolesController as rolesCtl"
      })
      .state('app.admin.security.roles.user', {
        url: "/userRoles?openedUsers&startFrom&startFromDomain&sortBy&order&substr&{pageSize:int}",
        params: {
          openedUsers: {
            array: true,
            dynamic: true
          },
          substr: {
            dynamic: true,
            value: ""
          },
          pageSize: {
            value: 20
          },
          startFrom: {
            value: null
          },
          startFromDomain: {
            value: null
          },
          sortBy: {
            value: "id",
            dynamic: true
          },
          order: {
            value: "asc",
            dynamic: true
          }
        },
        controller: "mnUserRolesController as userRolesCtl",
        templateUrl: "app/mn_admin/mn_security/mn_user_roles/mn_user_roles.html",
        data: {
          compat: "atLeast50"
        }
      })
      .state('app.admin.security.roles.groups', {
        // url: "/userRoles?openedUsers&startFrom&startFromDomain&{pageSize:int}",
        url: "/rolesGroups?startFrom&sortBy&order&substr&{pageSize:int}",
        params: {
          openedRolesGroups: {
            array: true,
            dynamic: true
          },
          substr: {
            dynamic: true,
            value: ""
          },
          pageSize: {
            value: 20
          },
          startFrom: {
            value: null
          },
          sortBy: {
            value: "id",
            dynamic: true
          },
          order: {
            value: "asc",
            dynamic: true
          }
        },
        controller: "mnRolesGroupsController as rolesGroupsCtl",
        templateUrl: "app/mn_admin/mn_security/mn_roles_groups.html",
        data: {
          compat: "atLeast50",
          enterprise: true
        }
      })
      .state('app.admin.security.internalRoles', {
        url: '/internalRoles',
        controller: 'mnInternalRolesController as internalRolesCtl',
        templateUrl: 'app/mn_admin/mn_security/mn_internal_roles/mn_internal_roles.html',
        data: {
          permissions: "cluster.admin.security.read",
          compat: "!atLeast50",
        }
      })
      .state('app.admin.security.session', {
        url: '/session',
        controller: 'mnSessionController as sessionCtl',
        templateUrl: 'app/mn_admin/mn_security/mn_session/mn_session.html',
        data: {
          permissions: "cluster.admin.security.read"
        }
      })
      .state('app.admin.security.rootCertificate', {
        url: '/rootCertificate',
        controller: 'mnRootCertificateController as rootCertificateCtl',
        templateUrl: 'app/mn_admin/mn_security/mn_root_certificate/mn_root_certificate.html',
        data: {
          enterprise: true
        }
      })
      .state('app.admin.security.clientCert', {
        url: '/clientCert',
        controller: 'mnClientCertController as clientCertCtl',
        templateUrl: 'app/mn_admin/mn_security/mn_client_certificate/mn_client_certificate.html',
        data: {
          compat: "atLeast50",
          enterprise: true
        }
      })
      .state('app.admin.security.audit', {
        url: '/audit',
        controller: 'mnAuditController as auditCtl',
        templateUrl: 'app/mn_admin/mn_security/mn_audit/mn_audit.html',
        data: {
          enterprise: true
        }
      })
      .state('app.admin.security.redaction', {
        url: '/redaction',
        controller: 'mnRedactionController as redactionCtl',
        templateUrl: 'app/mn_admin/mn_security/mn_redaction/mn_redaction.html',
        data: {
          compat: "atLeast55",
          enterprise: true
        }
      });
  }
})();
