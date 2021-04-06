import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnHelperService} from "./mn.helper.service.js";

export {MnXDCRAddRepScopeComponent};

class MnXDCRAddRepScopeComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-add-rep-scope",
      templateUrl: "/ui/app/mn.xdcr.add.rep.scope.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item",
        "explicitMappingGroup",
        "explicitMappingRules"
      ]
    })
  ]}


  static get parameters() { return [
    MnHelperService
  ]}

  constructor(mnHelperService) {
    super();
    this.toggler = mnHelperService.createToggle();
  }
}
