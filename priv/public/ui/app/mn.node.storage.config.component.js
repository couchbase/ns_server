import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnWizardService} from './mn.wizard.service.js';
import {FormControl} from "/ui/web_modules/@angular/forms.js";
import {BehaviorSubject} from '/ui/web_modules/rxjs.js';
import {takeUntil, pluck, distinctUntilChanged} from '/ui/web_modules/rxjs/operators.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnNodeStorageConfigComponent};

class MnNodeStorageConfigComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-node-storage-config",
      templateUrl: "/ui/app/mn.node.storage.config.html",
      inputs: [
        "group",
        "isHostCfgEnabled"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnWizardService,
    MnPoolsService
  ]}

  constructor(mnWizardService, mnPoolsService) {
    super();
    this.focusFieldSubject = new BehaviorSubject(true);
    this.hostnameHttp = mnWizardService.stream.hostnameHttp;
    this.diskStorageHttp = mnWizardService.stream.diskStorageHttp;
    this.setupNetConfigHttp = mnWizardService.stream.setupNetConfigHttp;
    this.enableExternalListenerHttp = mnWizardService.stream.enableExternalListenerHttp;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;
  }

  ngOnInit() {
    if (!this.isHostCfgEnabled) {
      return;
    }
    this.group.valueChanges
      .pipe(pluck("hostConfig", "afamily"),
            distinctUntilChanged(),
            takeUntil(this.mnOnDestroy))
      .subscribe((afamily) => {
        var hostname = this.group.get("hostname").value;
        if (afamily && hostname == "127.0.0.1") {
          this.group.get("hostname").setValue("::1");
        }
        if (!afamily && hostname == "::1") {
          this.group.get("hostname").setValue("127.0.0.1");
        }
      });
  }

  addCbasPathField() {
    var last = this.group.get('storage.cbas_path').length - 1;

    this.group
      .get('storage.cbas_path')
      .push(new FormControl(this.group.get('storage.cbas_path').value[last]));
  }

  removeCbasPathField() {
    var last = this.group.get('storage.cbas_path').length - 1;
    this.group.get('storage.cbas_path').removeAt(last);
  }
}
