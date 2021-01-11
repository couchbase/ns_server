import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {map, mapTo, takeUntil, withLatestFrom,
        filter, skip} from '/ui/web_modules/rxjs/operators.js';
import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {Subject, merge, } from "/ui/web_modules/rxjs.js";


export {MnKeyspaceSelectorComponent};

class MnKeyspaceSelectorComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-keyspace-selector",
      templateUrl: "/ui/app/mn.keyspace.selector.html",
      inputs: [
        "service"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush,
      host: {
        '(click)': '$event.stopPropagation()',
      }
    })
  ]}

  static get parameters() { return [
  ]}

  constructor() {
    super();
    this.select = new Subject();
  }

  ngOnInit() {
    this.select
      .pipe(withLatestFrom(this.service.stream.step),
            takeUntil(this.mnOnDestroy))
      .subscribe(([item, step]) => {
        this.service.setResultItem(item, step);
      });
  }
}
