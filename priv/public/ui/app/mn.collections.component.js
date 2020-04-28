import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {filter, map, switchMap} from '/ui/web_modules/rxjs/operators.js';
import {BehaviorSubject, Subject, pipe, empty} from '/ui/web_modules/rxjs.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnCollectionsService} from './mn.collections.service.js';


export {MnCollectionsComponent};

class MnCollectionsComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.collections.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnCollectionsService
  ]}

  constructor(mnCollectionsService) {
    super();
  }
}
