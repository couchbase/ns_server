import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnWizardService} from './mn.wizard.service.js';
import {FormControl} from "/ui/web_modules/@angular/forms.js";
import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnNodeStorageConfigComponent};

class MnNodeStorageConfigComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-node-storage-config",
      templateUrl: "/ui/app/mn.node.storage.config.html",
      inputs: [
        "group"
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
    this.diskStorageHttp = mnWizardService.stream.diskStorageHttp;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;
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
