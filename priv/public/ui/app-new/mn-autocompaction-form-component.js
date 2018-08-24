var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnAutocompactionForm =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnAutocompactionForm, mn.helper.MnEventableComponent);

    MnAutocompactionForm.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-autocompaction-form.html",
        inputs: [
          "group",
          "isBucketsSettings"
        ],
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnAutocompactionForm.parameters = [
      mn.services.MnAdmin,
      mn.services.MnBuckets,
      mn.services.MnPermissions,
      mn.services.MnPools,
      mn.services.MnWizard
    ];

    return MnAutocompactionForm;

    function MnAutocompactionForm(mnAdminService, mnBucketsService, mnPermissionsService, mnPoolsService, mnWizardService) {
      mn.helper.MnEventableComponent.call(this);
      this.mnAdminService = mnAdminService;

      this.isEnterprise = mnPoolsService.stream.isEnterprise;
      this.compatVersion = mnAdminService.stream.compatVersion;
      this.getIndexes = mnWizardService.stream.getIndexes;
      this.daysOfWeek = mn.helper.daysOfWeek;

      var settingsWrite =
          mnPermissionsService.createPermissionStream("settings!write");

      var settingsIndexesWrite =
          mnPermissionsService.createPermissionStream("settings.indexes!read");

      this.mnOnInit.pipe(
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(onInit.bind(this));

      function onInit() {
        Rx.combineLatest(
          settingsWrite,
          this.group.valueChanges
        ).pipe(
          Rx.operators.takeUntil(this.mnOnDestroy)
        ).subscribe(function () {
          var settingsWritePermission = value[0];
          var formGroup = value[1];

          if (!settingsWritePermission) {
            this.group.get("allowedTimePeriodFlag")
              .disable({onlySelf: true});
            this.group.get("parallelDBAndViewCmopaction")
              .disable({onlySelf: true});
            this.group.get("indexCircularCompactionFlag")
              .disable({onlySelf: true});
            this.group.get("purgeInterval")
              .disable({onlySelf: true});
          }

          (["viewFragmentationThreshold", "databaseFragmentationThreshold"])
            .forEach(forEachFieldName.bind(this));

          this.daysOfWeek.forEach(function (day) {
            toggleIfCondition(!this.group.get("indexCircularCompactionFlag").value ||
                              !settingsWritePermission,
                              "indexCircularCompactionDaysOfWeek." + day);
          });

          var isFragmentationProvided =
              isFragmentationProvided(this.group.get("viewFragmentationThreshold")) ||
              isFragmentationProvided(this.group.get("databaseFragmentationThreshold"));

          toggleIfCondition(
            !isFragmentationProvided || !settingsWritePermission, "allowedTimePeriodFlag");

          if (!isFragmentationProvided) {
            this.group.get("allowedTimePeriodFlag").setValue(false);
          }

          toggleIfCondition(this.group.get("indexCircularCompactionFlag").value ||
                            !settingsWritePermission,
                            "indexFragmentationThreshold.percentage");

          function maybeDisableFragmentationFields(groupName) {
            (["percentage", "size"]).forEach(forEachfieldName.bind(this))

            function forEachFieldName(fieldName) {
              if (!settingsWritePermission) {
                this.group.get(groupName + "." + fieldName + "Flag")
                  .disable({onlySelf: true});
              }
              toggleIfCondition(
                !this.group.get(groupName + "." + fieldName + "Flag").value ||
                  !settingsWritePermission,
                groupName + "." + fieldName
              );
            }
          }

          function isFragmentationProvided(group) {
            return (group.get("percentageFlag").value && group.get("percentage").value) ||
              (group.get("sizeFlag").value && group.get("size").value);
          }

          function toggleIfCondition(condition, field) {
            if (condition) {
              this.group.get(field).disable({onlySelf: true});
            } else {
              this.group.get(field).enable({onlySelf: true});
            }
          }
        });
      }

      // $scope.daysOfWeek = daysOfWeek;
      // $scope.rbac = mnPermissions.export;
      // $scope.poolDefault = mnPoolDefault.export;
      // $scope.maybeDisableTimeInterval = maybeDisableTimeInterval;
      // $scope.props = {};

      // if (mnPoolDefault.export.compat.atLeast40 && $scope.rbac.cluster.settings.indexes.read) {
      //   mnPromiseHelper($scope, mnSettingsClusterService.getIndexSettings())
      //     .applyToScope("indexSettings");
      // }

      // function maybeDisableTimeInterval() {
      //   $scope.props.isFragmentationProvided =
      //     isFragmentationProvided($scope.autoCompactionSettings.databaseFragmentationThreshold) ||
      //     isFragmentationProvided($scope.autoCompactionSettings.viewFragmentationThreshold);
      //   if (!$scope.props.isFragmentationProvided) {
      //     $scope.autoCompactionSettings.allowedTimePeriodFlag = false;
      //   }
      // }
    }

  })(window.rxjs);
