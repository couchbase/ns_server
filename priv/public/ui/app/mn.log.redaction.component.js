import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {pluck, map, takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnSecurityService} from './mn.security.service.js';
import {MnFormService} from './mn.form.service.js';

export {MnLogRedactionComponent};

class MnLogRedactionComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.log.redaction.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnSecurityService,
    MnFormService,
    MnPermissions
  ]}

  constructor(mnSecurityService, mnFormService, mnPermissions) {
    super();

    this.postLogRedaction = mnSecurityService.stream.postLogRedaction;

    this.form = mnFormService.create(this);

    this.form
      .setFormGroup({logRedactionLevel: ""})
      .setSource(mnSecurityService.stream.getLogRedaction)
      .setPackPipe(map(this.getValue.bind(this)))
      .setPostRequest(this.postLogRedaction)
      .successMessage("Settings saved successfully!")
      .clearErrors();

    this.form.group.disable();

    this.isDisabled =
      mnSecurityService.stream.getLogRedaction
      .pipe(map(v => mnPermissions.export.cluster.admin.security.write));

    this.isDisabled
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableField.bind(this));
  }

  maybeDisableField(value) {
    this.form.group[value ? "enable" : "disable"]();
  }

  getValue() {
    return {logRedactionLevel: this.form.group.get("logRedactionLevel").value};
  }
}
