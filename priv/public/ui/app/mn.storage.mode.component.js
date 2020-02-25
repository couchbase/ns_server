import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {combineLatest, of} from '/ui/web_modules/rxjs.js';
import {takeUntil, map, first} from '/ui/web_modules/rxjs/operators.js';
import _ from '/ui/web_modules/lodash.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import * as R from '/ui/web_modules/ramda.js';

export {MnStorageModeComponent};

class MnStorageModeComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-storage-mode",
      templateUrl: "/ui/app/mn.storage.mode.html",
      inputs: [
        "control",
        "indexFlagChanges",
        "permissionsIndexWrite"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnWizardService,
    MnPoolsService
  ]}

  constructor(mnWizardService, mnPoolsService) {
    super();
    this.indexesHttp = mnWizardService.stream.indexesHttp;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;
  }

  ngOnInit() {
    var isNotEnterprise = this.isEnterprise.pipe(map(R.not));

    var isFirstValueForestDB =
        this.control.valueChanges
        .pipe(first(),
              map((v) => v === 'forestdb'));

    this.showForestDB =
      combineLatest(
        isNotEnterprise,
        isFirstValueForestDB
      )
      .pipe(map(_.curry(_.some)(_, Boolean)));

    this.showPlasma = this.isEnterprise;

    combineLatest(
      isNotEnterprise,
      (this.indexFlagChanges || of(true)).pipe(map(R.not)),
      (this.permissionsIndexWrite || of(true)).pipe(map(R.not))
    ).pipe(
      map(_.curry(_.some)(_, Boolean)),
      takeUntil(this.mnOnDestroy)
    ).subscribe(this.doDisableControl.bind(this));
  }

  doDisableControl(value) {
    this.control[value ? "disable" : "enable"]();
  }
}
