import { BehaviorSubject, Subject } from '../web_modules/rxjs.js';

export { MnLifeCycleHooksToStream };

let componentLifecycleHooks = [
  "OnChanges",
  "OnInit",
  "DoCheck",
  "AfterContentInit",
  "AfterContentChecked",
  "AfterViewInit",
  "AfterViewChecked",
  "OnDestroy"
];

class MnLifeCycleHooksToStream {
  constructor() {
    componentLifecycleHooks.forEach((name) => {
      //OnChanges triggers before OnInit, so we should keep current value
      this["mn" + name] = (name === "OnChanges") ? new BehaviorSubject() : new Subject();
    });
  }
}

componentLifecycleHooks.forEach(function (name) {
  if (name === "OnDestroy") {
    MnLifeCycleHooksToStream.prototype["ng" + name] = function (value) {
      this["mn" + name].next();
      this["mn" + name].complete(value);
    }
  } else {
    MnLifeCycleHooksToStream.prototype["ng" + name] = function (value) {
      this["mn" + name].next(value);
    }
  }
});
