var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnServers =
  (function (Rx) {
    "use strict";

    mn.core.extend(MnServers, mn.core.MnEventableComponent);

    MnServers.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-servers.html",
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnServers.parameters = [
      mn.services.MnAdmin,
      mn.services.MnHelper,
      mn.services.MnPermissions,
      mn.services.MnSettings,
      mn.services.MnForm,
      mn.services.MnTasks,
      mn.services.MnServers
    ];

    MnServers.prototype.trackByFn = trackByFn

    return MnServers;

    function trackByFn(node) {
      return node.otpNode;
    }

    function MnServers(mnAdminService, mnHelperService, mnPermissionsService, mnSettingsService, mnFormService, mnTasksService, mnServersService) {
      mn.core.MnEventableComponent.call(this)

      this.formHelper = new ng.forms.FormGroup({
        searchTerm: new ng.forms.FormControl("")
      });

      this.onSortByClick = new Rx.BehaviorSubject("name");
      this.toggleFailover = new mnHelperService.createToggle();
      this.tasksRead = mnPermissionsService.createPermissionStream("tasks!read");
      this.poolsWrite = mnPermissionsService.createPermissionStream("pools!write");
      this.settingsWrite = mnPermissionsService.createPermissionStream("settings!write");
      this.settingsRead = mnPermissionsService.createPermissionStream("settings!read");
      this.failoverWarnings = mnAdminService.stream.failoverWarnings;
      this.isRebalancing = mnAdminService.stream.isRebalancing;
      this.isNotCompatMode = mnAdminService.stream.isNotCompatMode;
      this.prettyClusterCompat = mnAdminService.stream.prettyClusterCompat;
      this.getAutoFailover = mnSettingsService.stream.getAutoFailover;
      this.isLoadingSampleBucket = mnTasksService.stream.isLoadingSampleBucket;
      this.activateNodesWithoutEjected = mnServersService.stream.activateNodesWithoutEjected;
      this.isRecoveryMode = mnTasksService.stream.isRecoveryMode;
      this.ejectedNodesLength = mnServersService.stream.ejectedNodesLength;
      this.isBalanced = mnAdminService.stream.isBalanced;
      this.isSubtypeGraceful = mnTasksService.stream.isSubtypeGraceful;
      var bucketName = mnTasksService.stream.tasksRecovery.pipe(Rx.operators.pluck("bucket"));
      this.bucketRecoveryWrite = mnPermissionsService.createPermissionStream("recovery!write",
                                                                             bucketName);
      this.nodes = mnServersService.stream.nodes
        .pipe(mnHelperService.sortByStream(this.onSortByClick));

      this.resetAutofaiover = mnFormService.create(this)
        .setPostRequest(new mn.core.MnPostGroupHttp({
          postAutoFailoverReset: mnSettingsService.stream.postAutoFailoverReset,
          postAutoReprovisionReset: mnSettingsService.stream.postAutoReprovisionReset
        }).addSuccess().addError())
        .successMessage("Auto-failover quota reset successfully!")
        .errorMessage('Unable to reset Auto-failover quota!');

      mnServersService.stream.ejectedNodes
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(mnServersService.stream.ejectedNodesByUI);

    }
  })(window.rxjs);
