var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnJoinCluster =
  (function () {
    "use strict";

    mn.helper.extends(MnJoinCluster, mn.helper.MnEventableComponent);

    MnJoinCluster.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/wizard/mn-join-cluster.html"
      })
    ];

    MnJoinCluster.parameters = [
      mn.services.MnWizard,
      mn.services.MnApp,
      mn.services.MnAuth,
      window['@uirouter/angular'].UIRouter
    ];

    return MnJoinCluster;

    function MnJoinCluster(mnWizardService, mnAppService, mnAuthService, uiRouter) {
      mn.helper.MnEventableComponent.call(this);

      this.focusFieldSubject = new Rx.BehaviorSubject("hostname");
      this.onSubmit = new Rx.Subject();
      this.submitted = this.onSubmit.mapTo(true);

      this.wizardForm = mnWizardService.wizardForm;
      this.mnAppLoding = mnAppService.stream.loading;

      this.joinClusterForm = mnWizardService.wizardForm.joinCluster;

      this.hostnameHttp = mnWizardService.stream.hostnameHttp;
      this.diskStorageHttp = mnWizardService.stream.diskStorageHttp;
      this.joinClusterHttp = mnWizardService.stream.joinClusterHttp;

      this.groupHttp =
        new mn.helper.MnPostGroupHttp({
          hostnameHttp: this.hostnameHttp,
          diskStorageHttp: this.diskStorageHttp
        })
        .addLoading()
        .addSuccess();

      this.groupHttp
        .loading
        .merge(this.joinClusterHttp.loading)
        .takeUntil(this.mnOnDestroy)
        .subscribe(this.mnAppLoding.next.bind(this.mnAppLoding));

      this.groupHttp
        .success
        .takeUntil(this.mnOnDestroy)
        .subscribe((function () {
          var data = mnWizardService.wizardForm.joinCluster.get("clusterAdmin").value;
          data.services =
            mnWizardService.getServicesValues(
              mnWizardService.wizardForm.joinCluster.get("services.flag")).join(",");

          mnWizardService.stream.joinClusterHttp.post(data);
        }).bind(this));

      this.joinClusterHttp
        .success
        .takeUntil(this.mnOnDestroy)
        .subscribe(function () {
          var data = mnWizardService.wizardForm.joinCluster.get("clusterAdmin").value;
          mnAuthService.stream.loginHttp.post(data);
        });

      mnAuthService.stream.loginHttp
        .success
        .takeUntil(this.mnOnDestroy)
        .subscribe(function () {
          uiRouter.urlRouter.sync();
        });

      this.onSubmit
        .do(this.groupHttp.clearErrors.bind(this.groupHttp))
        .filter(isValid.bind(this))
        .filter(isNotLoading.bind(this))
        .map(getValues.bind(this))
        .takeUntil(this.mnOnDestroy)
        .subscribe(this.groupHttp.post.bind(this.groupHttp));

      function isNotLoading() {
        return !this.mnAppLoding.getValue();
      }

      function isValid() {
        return !this.joinClusterForm.invalid;
      }

      function getValues() {
        return {
          hostnameHttp: this.wizardForm.joinCluster.get("clusterStorage.hostname").value,
          diskStorageHttp: this.wizardForm.joinCluster.get("clusterStorage.storage").value
        };
      }
    }
  })();
