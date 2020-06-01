import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {pluck, scan, distinctUntilChanged, shareReplay,
        takeUntil, startWith, map} from '/ui/web_modules/rxjs/operators.js';
import {Subject, combineLatest} from '/ui/web_modules/rxjs.js';
import {not, pipe, contains, all, equals} from '/ui/web_modules/ramda.js';
import {FormControl, FormGroup} from '/ui/web_modules/@angular/forms.js';

import { MnLifeCycleHooksToStream } from './mn.core.js';

export {MnAuditItemComponent};

class MnAuditItemComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-audit-item",
      templateUrl: "/ui/app/mn.audit.item.html",
      inputs: [
        "form",
        "descriptors",
        "moduleName"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  constructor() {
    super();
    this.onToggleClick = new Subject();
    this.toggleSection = this.onToggleClick.pipe(scan(not, false),
                                                 shareReplay({refCount: true, bufferSize: 1}));
  }

  ngOnInit() {
    this.formHelper = new FormGroup({
      toggleAll: new FormControl()
    });
    this.thisDescriptors = this.descriptors.pipe(pluck(this.moduleName));
    var thisDescriptorsByID = this.thisDescriptors
        .pipe(map(desc => desc.reduce((acc, item) => {
          acc[item.id] = item;
          return acc;
        }, {})));

    combineLatest(this.thisDescriptors, thisDescriptorsByID)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.generateForm.bind(this));

    var thisModuleGroup = this.form.group.get("descriptors").get(this.moduleName);


    this.thisModuleChanges =
      thisModuleGroup.valueChanges.pipe(startWith(thisModuleGroup.getRawValue()),
                                        map(() => thisModuleGroup.getRawValue()));

    this.isAuditEnabled =
      this.form.group.valueChanges.pipe(pluck("auditdEnabled"),
                                        distinctUntilChanged());

    this.isAuditEnabled
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableToggleAll.bind(this));

    combineLatest(this.isAuditEnabled, thisDescriptorsByID)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableFields.bind(this));

    this.isThereEnabledField =
      this.thisModuleChanges.pipe(map(pipe(Object.values, contains(true))),
                                  shareReplay({refCount: true, bufferSize: 1}));

    this.thisModuleChanges
      .pipe(map(pipe(Object.values, all(equals(true)))),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.setToggleAllValue.bind(this));

    combineLatest(this.formHelper.get("toggleAll").valueChanges, thisDescriptorsByID)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.doToggleAll.bind(this));

  }

  maybeDisableToggleAll(value) {
    var method = value ? "enable" : "disable";
    this.formHelper.get("toggleAll")[method]({emitEvent: false});
  }

  maybeDisableFields(value) {
    var controls = this.form.group.get("descriptors").get(this.moduleName).controls;
    Object.keys(controls).forEach(controlID => {
      var method = !value[1][controlID].nonFilterable && value[0]  ? "enable" : "disable";
      controls[controlID][method]({emitEvent: false});
    });
  }

  setToggleAllValue(value) {
    this.formHelper.get("toggleAll").setValue(value, {emitEvent: false});
  }

  doToggleAll(value) {
    var thisModule = this.form.group.get("descriptors").get(this.moduleName);
    var ids = Object.keys(thisModule.value);
    thisModule.patchValue(ids.reduce((acc, key) => {
      acc[key] = value[1][key].nonFilterable || value[0];
      return acc;
    }, {}));
  }

  generateForm(descriptors) {
    this.form.group.get("descriptors")
      .addControl(this.moduleName, new FormGroup(
        descriptors[0].reduce(function (acc, item) {
          acc[item.id] = new FormControl({
            value: item.value,
            disabled: descriptors[1][item.id].nonFilterable
          });
          return acc;
        }.bind(this), {})
      ));
  }

  mapNames(name) {
    switch (name) {
    case "auditd":
      return "Audit";
    case "ns_server":
      return "REST API";
    case "n1ql":
      return "Query and Index Service";
    case "eventing":
      return "Eventing Service";
    case "memcached":
      return "Data Service";
    case "xdcr":
      return name.toUpperCase();
    case "fts":
      return "Search Service";
    case "view_engine":
      return "Views";
    default:
      return name.charAt(0).toUpperCase() + name.substr(1).toLowerCase();
    }
  }
}
