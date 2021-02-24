import { ChangeDetectionStrategy, Component } from '/ui/web_modules/@angular/core.js';
import { MnLifeCycleHooksToStream } from "./mn.core.js";
import { startWith } from '/ui/web_modules/rxjs/operators.js';
import { BehaviorSubject } from '/ui/web_modules/rxjs.js';

export { MnSelectComponent };

class MnSelectComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-select",
      templateUrl: "app/mn.select.html",
      inputs: [
        "group",
        "mnFormControlName",
        "values",
        "labels",
        "filter",
        "capitalize",
        "mnPlaceholder",
        "placement"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
  ]}

  constructor() {
    super();
  }

  ngOnInit() {
    this.dropdownFormControl = this.group.get(this.mnFormControlName);
    if (this.dropdownFormControl) {
      this.disabled = new BehaviorSubject(this.dropdownFormControl.disabled);
    }

    if (!this.filter) {
      this.filter = this.defaultFilter;
    }

    this.placement = this.placement || 'bottom';

    let field = this.group.get(this.mnFormControlName);
    this.value = field.valueChanges.pipe(startWith(field.value));
    field.registerOnDisabledChange(disabled => this.disabled.next(disabled));
  }

  /**
   * Default filter:
   * * if capitalize input flag is true - capitalize the displayed label if it is a string
   * * else leave the label as it is
   * @param option
   * @returns {string}
   */
  defaultFilter(option) {
    if (this.capitalize && angular.isString(option) && option) {
      return option[0].toUpperCase() + option.slice(1);
    }

    return option;
  }

  optionClicked(value) {
    this.dropdownFormControl.setValue(value);
  }

  arrowClicked(event) {
    if (this.disabled.getValue()) {
      event.stopPropagation();
    }
  }
}
