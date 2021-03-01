import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {map, mapTo, takeUntil, withLatestFrom,
        filter, skip} from '/ui/web_modules/rxjs/operators.js';
import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {Subject, merge, } from "/ui/web_modules/rxjs.js";
import {MnFormService} from "./mn.form.service.js";

export {MnKeyspaceSelectorComponent};

class MnKeyspaceSelectorComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-keyspace-selector",
      templateUrl: "/ui/app/mn.keyspace.selector.html",
      inputs: [
        "service",
        "defaults"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush,
      host: {
        '(click)': '$event.stopPropagation()',
      }
    })
  ]}

  static get parameters() { return [
    MnFormService
  ]}

  constructor(mnFormService) {
    super();
    this.form = mnFormService.create(this).setFormGroup({}).hasNoPostRequest();
  }

  ngOnInit() {
    this.defaults && this.service.setKeyspace(this.defaults);

    this.form.submit
      .pipe(withLatestFrom(this.service.stream.step),
            takeUntil(this.mnOnDestroy))
      .subscribe(([item, step]) => {
        this.service.setResultItem(item, step);
      });
  }
}
