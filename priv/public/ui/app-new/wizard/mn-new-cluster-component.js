var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnNewCluster =
  (function () {
    "use strict";

    mn.helper.extends(MnNewClusterComponent, mn.helper.MnEventableComponent);

    MnNewClusterComponent.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/wizard/mn-new-cluster.html"
      })
    ];

    MnNewClusterComponent.parameters = [
      mn.services.MnWizard,
      window['@uirouter/angular'].UIRouter
    ];

    return MnNewClusterComponent;

    function MnNewClusterComponent(mnWizardService, uiRouter) {
      mn.helper.MnEventableComponent.call(this);

      this.onSubmit = new Rx.Subject();
      this.focusFieldSubject = new Rx.BehaviorSubject("clusterName");

      this.submitted = this.onSubmit.mapTo(true);
      this.authHttp = mnWizardService.stream.authHttp;
      this.newClusterForm = mnWizardService.wizardForm.newCluster;
      this.newClusterForm.setValidators([mn.helper.validateEqual("user.password",
                                                                 "user.passwordVerify",
                                                                 "passwordMismatch")]);
      this.authHttp
        .success
        .takeUntil(this.mnOnDestroy)
        .subscribe(onSuccess.bind(this));

      this.onSubmit
        .filter(canSubmit.bind(this))
        .map(getValues.bind(this))
        .takeUntil(this.mnOnDestroy)
        .subscribe(this.authHttp.post.bind(this.authHttp));

      function getValues() {
        return [this.newClusterForm.value.user, true];
      }

      function canSubmit() {
        return !this.newClusterForm.invalid;
      }

      function onSuccess() {
        uiRouter.stateService.go('app.wizard.termsAndConditions', null, {location: false});
      }
    }
  })();
