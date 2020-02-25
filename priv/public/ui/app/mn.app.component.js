import { Component } from '../web_modules/@angular/core.js';

export { MnAppComponent };

class MnAppComponent {
  static get annotations() { return [
    new Component({
      selector: "mn-app",
      template: '<ui-view class="root-container"></ui-view>'
    })
  ]}

  constructor() {
  }
}
