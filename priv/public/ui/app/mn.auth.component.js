import { Component, ChangeDetectionStrategy } from '/ui/web_modules/@angular/core.js';
import { FormGroup, FormControl, Validators } from '/ui/web_modules/@angular/forms.js';
import { BehaviorSubject } from '/ui/web_modules/rxjs.js';
import { MnAuthService } from './mn.auth.service.js';
import { MnFormService } from './mn.form.service.js';
import { UIRouter } from '/ui/web_modules/@uirouter/angular.js';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnPools } from "./ajs.upgraded.providers.js";

export { MnAuthComponent };

class MnAuthComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "app/mn.auth.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnFormService,
    MnAuthService,
    UIRouter,
    MnPools
  ]}

  constructor(mnFormService, mnAuthService, uiRouter, mnPools) {
    super();
    this.focusFieldSubject = new BehaviorSubject(true);

    this.postUILogin = mnAuthService.stream.postUILogin;

    this.form = mnFormService.create(this)
      .setFormGroup({
        user: ['', Validators.required],
        password: ['', Validators.required]})
      .setPostRequest(this.postUILogin)
      .success(() => {
        mnPools.clearCache();
        uiRouter.urlRouter.sync();
      });
  }
}
