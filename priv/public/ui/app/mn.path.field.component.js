import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {MnWizardService} from './mn.wizard.service.js';
import {BehaviorSubject} from '/ui/web_modules/rxjs.js';

export {MnPathFieldComponent};

class MnPathFieldComponent {
  static get annotations() { return [
    new Component({
      selector: "mn-path-field",
      templateUrl: "/ui/app/mn.path.field.html",
      inputs: [
        "control",
        "controlName"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnWizardService
  ]}

  ngOnInit() {
    this.lookUpPath = this.createLookUpStream(this.control.valueChanges);
    setTimeout(function () {
      //trigger storageGroup.valueChanges for lookUpIndexPath,lookUpDBPath
      this.control.setValue(this.control.value);
    }.bind(this), 0);
  }

  constructor(mnWizardService) {
    this.focusFieldSubject = new BehaviorSubject(true);
    this.createLookUpStream = mnWizardService.createLookUpStream.bind(mnWizardService);
  }
}
