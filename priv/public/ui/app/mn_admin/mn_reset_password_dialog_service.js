/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import angular from "angular";
import uiBootstrap from "angular-ui-bootstrap";
import template from "./mn_reset_password_dialog.html";

export default "mnResetPasswordDialogService";

angular
  .module("mnResetPasswordDialogService", [uiBootstrap])
  .factory("mnResetPasswordDialogService", ["$http", "$uibModal", "$q", mnResetPasswordDialogFactory]);

function mnResetPasswordDialogFactory($http, $uibModal, $q) {
  var mnResetPasswordDialogService = {
    post: post,
    showDialog: showDialog
  };

  return mnResetPasswordDialogService;

  function showDialog(user) {
    $uibModal.open({
      template,
      controller: "mnResetPasswordDialogController as resetPasswordDialogCtl",
      resolve: {
        user: function () {
          return user;
        }
      }
    });
  }

  function post(user) {
    return $http({
      headers: {
        'Authorization': "Basic " + btoa(user.name + ":" + user.currentPassword),
        'ns-server-ui': undefined
      },
      url: "/controller/changePassword",
      method: "POST",
      data: {
        password: user.password
      }
    }).then(function (resp) {
      return resp.data;
    }, function (resp) {
      if (resp.status === 401) {
        return $q.reject("Incorrect user password");
      } else {
        return $q.reject(resp);
      }
    });
  }
}
