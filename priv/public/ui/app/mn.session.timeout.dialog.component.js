import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {FormGroup} from '/ui/web_modules/@angular/forms.js';
import {interval} from '/ui/web_modules/rxjs.js';
import {NgbActiveModal} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {scan, startWith} from '/ui/web_modules/rxjs/operators.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnSessionTimeoutDialogComponent};

class MnSessionTimeoutDialogComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.session.timeout.dialog.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    NgbActiveModal
  ]}

  constructor(activeModal) {
    super();
    this.activeModal = activeModal;
    this.formGroup = new FormGroup({});
    var time = (Number(localStorage.getItem("uiSessionTimeout")) - 30000) / 1000;
    this.time = interval(1000).pipe(scan(acc => --acc, time), startWith(time));
  }
}
