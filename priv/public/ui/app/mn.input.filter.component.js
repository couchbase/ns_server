import { ChangeDetectionStrategy, Component} from '/ui/web_modules/@angular/core.js';

export { MnInputFilterComponent };

class MnInputFilterComponent {
  static get annotations() { return [
    new Component({
      selector: "mn-input-filter",
      templateUrl: "app/mn.input.filter.html",
      inputs: [
        "group",
        "placeholder"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}
}
