import angular from "/ui/web_modules/angular.js";
import mnUserRoles from "./mn_user_roles_controller.js";
import mnAudit from "./mn_audit_controller.js";
import mnRootCertificate from "./mn_root_certificate_controller.js";
import mnRedaction from "./mn_redaction_controller.js";
import mnClientCertificate from "./mn_client_certificate_controller.js";
import mnRolesGroups from "./mn_roles_groups_controller.js";
import mnElementCrane from "/ui/app/components/directives/mn_element_crane/mn_element_crane.js";
import mnPluggableUiRegistry from "/ui/app/components/mn_pluggable_ui_registry.js";
import mnSession from "./mn_session_controller.js";

export default 'mnSecurity';

angular
  .module('mnSecurity', [
    mnAudit,
    mnSession,
    mnUserRoles,
    mnRootCertificate,
    mnRedaction,
    mnClientCertificate,
    mnRolesGroups,
    mnElementCrane,
    mnPluggableUiRegistry
  ])
  .config(mnIndexesConfig)
  .controller("mnSecurityController", mnSecurityController);

function mnSecurityController(poolDefault) {
  var vm = this;
  vm.poolDefault = poolDefault;
}

function mnIndexesConfig($stateProvider) {
  $stateProvider
    .state('app.admin.security', {
      abstract: true,
      url: "/security",
      views: {
        "main@app.admin": {
          controller: "mnSecurityController as securityCtl",
          templateUrl: "app/mn_admin/mn_security.html"
        }
      },
      data: {
        permissions: "cluster.admin.security.read",
        title: "Security"
      }
    })
    .state('app.admin.security.roles', {
      abstract: true,
      templateUrl: "app/mn_admin/mn_roles.html",
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
      templateUrl: "app/mn_admin/mn_user_roles.html"
    })
    .state('app.admin.security.roles.groups', {
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
      templateUrl: "app/mn_admin/mn_roles_groups.html",
      data: {
        enterprise: true
      }
    })
    .state('app.admin.security.rootCertificate', {
      url: '/rootCertificate',
      controller: 'mnRootCertificateController as rootCertificateCtl',
      templateUrl: 'app/mn_admin/mn_root_certificate.html',
      data: {
        enterprise: true
      }
    })
    .state('app.admin.security.clientCert', {
      url: '/clientCert',
      controller: 'mnClientCertController as clientCertCtl',
      templateUrl: 'app/mn_admin/mn_client_certificate.html',
      data: {
        enterprise: true
      }
    });
}
