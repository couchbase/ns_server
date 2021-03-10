import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {combineLatest, of} from '/ui/web_modules/rxjs.js';
import {takeUntil, map, first, startWith, filter} from '/ui/web_modules/rxjs/operators.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import {not, any, all} from '/ui/web_modules/ramda.js';

export {MnStorageModeComponent};

class MnStorageModeComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-storage-mode",
      templateUrl: "/ui/app/mn.storage.mode.html",
      inputs: [
        "control",
        "indexFlag",
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
    var isNotEnterprise = this.isEnterprise.pipe(map(not));
    var isFirstValueForestDB = this.control.valueChanges.pipe(startWith(this.control.value),
                                                              filter(v => !!v),
                                                              first(),
                                                              map(v => v == "forestdb"));
    var indexFlag = this.indexFlag ?
        this.indexFlag.valueChanges.pipe(startWith(this.indexFlag.value)) : of(true);

    this.showForestDB =
      combineLatest(isNotEnterprise, isFirstValueForestDB)
      .pipe(map(any(Boolean)));

    combineLatest(this.isEnterprise, indexFlag, this.permissionsIndexWrite || of(true))
      .pipe(map(all(Boolean)),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.doDisableControl.bind(this));
  }

  doDisableControl(value) {
    this.control[value ? "enable" : "disable"]();
  }
}
