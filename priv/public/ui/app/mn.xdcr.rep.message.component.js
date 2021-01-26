import { Component, ChangeDetectionStrategy } from '/ui/web_modules/@angular/core.js';

export { MnXDCRRepMessageComponent };

class MnXDCRRepMessageComponent {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-rep-message",
      templateUrl: "/ui/app/mn.xdcr.rep.message.html",
      inputs: [
        "fromBucket",
        "toCluster"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return []}

  constructor() {}
}
