import { Component, ChangeDetectionStrategy } from '/ui/web_modules/@angular/core.js';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnAdminService } from './mn.admin.service.js';
import { BehaviorSubject } from '/ui/web_modules/rxjs.js';

export { MnWelcomeComponent };

class MnWelcomeComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.welcome.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnAdminService
  ]}

  constructor(mnAdmin) {
    super();
    this.focusFieldSubject = new BehaviorSubject(true);
    this.prettyVersion = mnAdmin.stream.prettyVersion;
  }
}
