import { ChangeDetectionStrategy, Component } from '/ui/web_modules/@angular/core.js';

export { MnInputFilterComponent };

class MnInputFilterComponent {
  static get annotations() { return [
    new Component({
      selector: "mn-input-filter",
      templateUrl: "app/mn.input.filter.html",
      inputs: [
        "group",
        "mnFocusStatus",
        "mnFocus",
        "mnClearDisabled",
        "mnPlaceholder",
        "mnName"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
  ]}

  constructor() {
  }

  onBlur() {
    this.mnFocusStatus && this.mnFocusStatus.next(false);
  }

  onFocus() {
    this.mnFocusStatus && this.mnFocusStatus.next(true);
  }
}
