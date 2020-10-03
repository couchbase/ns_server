import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {takeUntil, filter, withLatestFrom,
        map, startWith} from '/ui/web_modules/rxjs/operators.js';
import {combineLatest} from '/ui/web_modules/rxjs.js';
import {FormBuilder} from '/ui/web_modules/@angular/forms.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnXDCRAddRepMappingComponent};

class MnXDCRAddRepMappingComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-add-rep-mapping",
      templateUrl: "/ui/app/mn.xdcr.add.rep.mapping.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item",
        "groups",
        "parent",
        "rulesHolder"
      ]
    })
  ]}

  static get parameters() { return [
    FormBuilder
  ]}

  constructor(formBuilder) {
    super();
    this.formBuilder = formBuilder;
  }

  ngOnInit() {
    if (this.parent) {
      this.group = this.groups.collections[this.parent];
      this.parentGroup = this.groups.scopes;
      this.controls = this.groups.collectionsControls[this.parent];
      if (!this.group.flags.get(this.item.name)) {
        let maybeDisabled = !!this.parentGroup.fields.get(this.parent).value;
        this.group.flags.addControl(
          this.item.name,
          this.formBuilder.control({value: true, disabled: maybeDisabled})
        );
        this.group.fields.addControl(
          this.item.name,
          this.formBuilder.control({value: this.item.name, disabled: maybeDisabled})
        );
      }
    } else {
      this.group = this.groups.scopes;
    }

    this.flag = this.group.flags.get(this.item.name);
    this.field = this.group.fields.get(this.item.name);

    this.flag.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.toggleFiled.bind(this));

    this.toggleFiled(this.flag.value);

    if (this.parent) {
      let denyModeControl = this.controls.get("denyMode");
      let denyModeStream = denyModeControl.valueChanges.pipe(startWith(denyModeControl.value));
      //collections behaviours
      this.parentFlag = this.parentGroup.flags.get(this.parent);
      this.parentField = this.parentGroup.fields.get(this.parent);
      let flagStream = this.flag.valueChanges.pipe(startWith(this.flag.value));

      combineLatest(flagStream, denyModeStream)
        .pipe(filter(v => this.parentFlag.value && v[0]),
              takeUntil(this.mnOnDestroy))
        .subscribe(this.setRule.bind(this));

      combineLatest(flagStream, denyModeStream)
        .pipe(filter(v => this.parentFlag.value && !v[0]),
              takeUntil(this.mnOnDestroy))
        .subscribe(this.deleteRule.bind(this));

      this.field.valueChanges
        .pipe(withLatestFrom(denyModeStream),
              takeUntil(this.mnOnDestroy))
        .subscribe(this.setRule.bind(this));

      this.parentFlag.valueChanges
        .pipe(filter(v => !v),
              map(v => [v, false]),
              takeUntil(this.mnOnDestroy))
        .subscribe(this.deleteRule.bind(this));
    }
  }

  setRule([_, denyMode]) {
    let from = this.parent + ":" + this.item.name;
    let to = this.parentField.value + ":" + this.field.value;
    if (denyMode) {
      if (from === to) {
        delete this.rulesHolder[from];
      } else {
        this.rulesHolder[from] = to;
      }
    } else {
      this.rulesHolder[from] = to;
    }
  }

  deleteRule([_, denyMode]) {
    if (denyMode) {
      this.rulesHolder[this.parent + ":" + this.item.name] = null;
    } else {
      delete this.rulesHolder[this.parent + ":" + this.item.name];
    }
  }

  toggleFiled(v) {
    this.field[v ? "enable" : "disable"]();
  }
}
