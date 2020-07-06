import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {combineLatest} from "/ui/web_modules/rxjs.js";

import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnPoolsService} from "./mn.pools.service.js";
import {MnAdminService} from "./mn.admin.service.js";
import {MnHelperService} from "./mn.helper.service.js";

export {MnXDCRSettingsComponent};

class MnXDCRSettingsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-settings",
      templateUrl: "/ui/app/mn.xdcr.settings.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "group",
        "type"
      ]
    })
  ]}

  static get parameters() { return [
    MnXDCRService,
    MnPoolsService,
    MnAdminService,
    MnHelperService
  ]}

  constructor(mnXDCRService, mnPoolsService, mnAdminService, mnHelperService) {
    super();

    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.compatVersion55 = mnAdminService.stream.compatVersion55;
    this.error = mnXDCRService.stream.postSettingsReplicationsValidation.error;

    this.toggler = mnHelperService.createToggle();
  }
}
