var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnNewCluster =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnNewClusterComponent, mn.helper.MnEventableComponent);

    MnNewClusterComponent.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-new-cluster.html",
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
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

      this.submitted = this.onSubmit.pipe(Rx.operators.mapTo(true));
      this.authHttp = mnWizardService.stream.authHttp;
      this.newClusterForm = mnWizardService.wizardForm.newCluster;
      this.newClusterForm.setValidators([mn.helper.validateEqual("user.password",
                                                                 "user.passwordVerify",
                                                                 "passwordMismatch")]);
      this.authHttp.success.pipe(
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(onSuccess.bind(this));

      this.onSubmit.pipe(
        Rx.operators.filter(canSubmit.bind(this)),
        Rx.operators.map(getValues.bind(this)),
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(this.authHttp.post.bind(this.authHttp));

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
  })(window.rxjs);
