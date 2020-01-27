import { ChangeDetectionStrategy,
         Directive,
         ElementRef } from '../web_modules/@angular/core.js';
import { BehaviorSubject } from '../web_modules/rxjs.js';
import { filter, takeUntil } from '../web_modules/rxjs/operators.js';
import { MnLifeCycleHooksToStream } from './mn.core.js';

export { MnFocusDirective };

class MnFocusDirective extends MnLifeCycleHooksToStream {
  static annotations = [
    new Directive({
      selector: "[mnFocus]",
      inputs: [
        "mnFocus"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ];

  static parameters = [ElementRef]

  constructor(el) {
    super();
    this.el = el.nativeElement;
    this.formControlName = this.el.getAttribute("formControlName");
  }

  ngOnInit() {
    this.mnFocus = this.mnFocus || new BehaviorSubject(true);
    this.mnFocus.pipe(
      filter(this.maybePrevent.bind(this)),
      takeUntil(this.mnOnDestroy)
    ).subscribe(this.doFocus.bind(this));
  }

  doFocus(value) {
    this.el.focus();
  }

  maybePrevent(value) {
    return (typeof value === "string") ? value === this.formControlName : value
  }

}
