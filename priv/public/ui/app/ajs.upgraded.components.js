import {Directive, ElementRef, Injector} from '/ui/web_modules/@angular/core.js';
import {UpgradeComponent} from '/ui/web_modules/@angular/upgrade/static.js';

export {MnDetailStatsDirective};

class MnDetailStatsDirective extends UpgradeComponent {
  static get annotations() { return [
    new Directive({
      selector: "mn-detail-stats",
      inputs: [
        "mnTitle",
        "bucket",
        "itemId",
        "service",
        "prefix",
        "nodeName"
      ]
    })
  ]}

  static get parameters() { return [
    ElementRef,
    Injector
  ]}

  constructor(elementRef, injector) {
    super('mnDetailStats', elementRef, injector);
  }

}
