var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnAuth =
  (function () {
    "use strict";

    mn.helper.extends(MnAuthComponent, mn.helper.MnEventableComponent);

    MnAuthComponent.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-auth.html",
      })
    ];

    MnAuthComponent.parameters = [
      mn.services.MnAuth,
      window['@uirouter/angular'].UIRouter,
      ng.forms.FormBuilder
    ];

    return MnAuthComponent;

    function MnAuthComponent(mnAuthService, uiRouter, formBuilder) {
      mn.helper.MnEventableComponent.call(this);

      this.focusFieldSubject = new Rx.BehaviorSubject(true);
      this.onSubmit = new Rx.Subject();

      this.loginHttp = mnAuthService.stream.loginHttp;
      this.logoutHttp = mnAuthService.stream.logoutHttp;

      this.loginHttp
        .success
        .takeUntil(this.mnOnDestroy)
        .subscribe(function () {
          uiRouter.urlRouter.sync();
        });

      this.authForm =
        formBuilder.group({
          user: ['', ng.forms.Validators.required],
          password: ['', ng.forms.Validators.required]
        });

      this.onSubmit
        .takeUntil(this.mnOnDestroy)
        .map(getValues.bind(this))
        .subscribe(this.loginHttp.post.bind(this.loginHttp));

      function getValues() {
        return this.authForm.value;
      }
    }

  })();
