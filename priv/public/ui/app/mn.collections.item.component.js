import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnCollectionsItemComponent};

class MnCollectionsItemComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-collections-item",
      templateUrl: "app/mn.collections.item.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "scope"
      ]
    })
  ]}

  static get parameters() { return [
  ]}

  constructor() {
    super();
  }
}
