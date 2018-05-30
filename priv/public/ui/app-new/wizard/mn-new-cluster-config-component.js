var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnNewClusterConfig =
  (function () {
    "use strict";

    mn.helper.extends(MnNewClusterConfig, mn.helper.MnEventableComponent);

    MnNewClusterConfig.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/wizard/mn-new-cluster-config.html"
      })
    ];

    MnNewClusterConfig.parameters = [
      mn.services.MnWizard,
      mn.services.MnAdmin,
      mn.services.MnPools,
      mn.services.MnApp,
      mn.services.MnAuth,
      window['@uirouter/angular'].UIRouter
    ];

    return MnNewClusterConfig;

    function MnNewClusterConfig(mnWizardService, mnAdminService, mnPoolsService, mnAppService, mnAuthService, uiRouter) {
      mn.helper.MnEventableComponent.call(this);

      this.focusField = true;
      this.onSubmit = new Rx.Subject();

      this.wizardForm = mnWizardService.wizardForm;

      this.mnAppLoding = mnAppService.stream.loading;

      this.newClusterConfigForm = mnWizardService.wizardForm.newClusterConfig;

      this.getServicesValues = mnWizardService.getServicesValues;

      this.totalRAMMegs = mnWizardService.stream.totalRAMMegs;
      this.maxRAMMegs = mnWizardService.stream.maxRAMMegs;

      this.servicesHttp = mnWizardService.stream.servicesHttp;
      this.groupHttp = mnWizardService.stream.groupHttp;
      this.initialValues = mnWizardService.initialValues;

      this.isButtonDisabled =
        mnAdminService.stream.poolsDefaultHttp
        .error
        .map(function (error) {
          return error && !_.isEmpty(error.errors);
        });

      mnWizardService.stream.groupHttp
        .loading
        .merge(mnWizardService.stream.secondGroupHttp.loading)
        .takeUntil(this.mnOnDestroy)
        .subscribe(this.mnAppLoding.next.bind(this.mnAppLoding));

      mnWizardService.stream.groupHttp
        .success
        .takeUntil(this.mnOnDestroy)
        .subscribe(function (result) {
          mnWizardService.stream.secondGroupHttp.post({
            indexesHttp: {
              storageMode: mnWizardService.wizardForm.newClusterConfig.get("storageMode").value
            },
            authHttp: [mnWizardService.wizardForm.newCluster.value.user, false]
          });
        });

      mnWizardService.stream.secondGroupHttp
        .success
        .takeUntil(this.mnOnDestroy)
        .subscribe(function () {
          mnAuthService.stream.loginHttp.post(mnWizardService.getUserCreds());
        })

      mnAuthService.stream.loginHttp
        .success
        .takeUntil(this.mnOnDestroy)
        .subscribe(function () {
          uiRouter.urlRouter.sync();
        });

      this.onSubmit
        .do(this.groupHttp.clearErrors.bind(this.groupHttp))
        .filter(isNotLoading.bind(this))
        .withLatestFrom(mnPoolsService.stream.isEnterprise)
        .map(getWizardValues.bind(this))
        .takeUntil(this.mnOnDestroy)
        .subscribe(this.groupHttp.post.bind(this.groupHttp));

      function isNotLoading() {
        return !this.mnAppLoding.getValue();
      }

      function getWizardValues(isEnterprise) {
        return {
          poolsDefaultHttp: [
            getPoolsDefaultValues.bind(this)(isEnterprise[1]),
            false
          ],
          servicesHttp: {
            services: this.getServicesValues(
              this.wizardForm.newClusterConfig.get("services.flag")
            ).join(","),
          },
          diskStorageHttp: this.wizardForm.newClusterConfig.get("clusterStorage.storage").value,
          hostnameHttp: this.wizardForm.newClusterConfig.get("clusterStorage.hostname").value,
          statsHttp: this.wizardForm.newClusterConfig.get("enableStats").value
        };
      }

      function getPoolsDefaultValues(isEnterprise) {
        var services = [
          ["memoryQuota", "kv"],
          ["indexMemoryQuota", "index"],
          ["ftsMemoryQuota", "fts"],
          ["cbasMemoryQuota", "cbas"]
        ];
        if (isEnterprise) {
          services.push(["eventingMemoryQuota", "eventing"]);
        }
        return _.reduce(services, getPoolsDefaultValue.bind(this), {
          clusterName: this.wizardForm.newCluster.get("clusterName").value
        });
      }

      function getPoolsDefaultValue(result, names) {
        var service = this.wizardForm.newClusterConfig.get("services.flag." + names[1]);
        if (service && service.value) {
          result[names[0]] =
            this.wizardForm.newClusterConfig.get("services.field." + names[1]).value;
        }
        return result;
      }
    }
  })();
