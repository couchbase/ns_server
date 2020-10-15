import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {takeUntil, filter, withLatestFrom, merge,
        map, startWith} from '/ui/web_modules/rxjs/operators.js';
import {combineLatest} from '/ui/web_modules/rxjs.js';
import {FormBuilder} from '/ui/web_modules/@angular/forms.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnXDCRAddRepMappingItemComponent};

class MnXDCRAddRepMappingItemComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-add-rep-mapping-item",
      templateUrl: "/ui/app/mn.xdcr.add.rep.mapping.item.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item",
        "groups",
        "parent",
        "explicitMappingRules"
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
        let maybeDisabled = !this.parentGroup.flags.get(this.parent).value;
        this.group.flags.addControl(
          this.item.name,
          this.formBuilder.control({
            value: this.controls.get("denyMode").value || maybeDisabled,
            disabled: maybeDisabled
          })
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
        .pipe(merge(this.parentField.valueChanges),
              withLatestFrom(denyModeStream),
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
    let sourceScope = this.parent;
    let sourceCollection = this.item.name;
    let source = sourceScope + ":" + sourceCollection;

    let targetScope = this.parentField.value;
    let targetCollection = this.field.value;
    let target = targetScope + ":" + targetCollection;

    let rules = this.explicitMappingRules.getValue();
    let collectionFlag = this.flag.value;

    if (denyMode) {
      if (collectionFlag) {
        if (sourceCollection === targetCollection) {
          delete rules[source];
        } else {
          rules[source] = target;
        }
      } else {
        rules[source] = null;
      }
    } else {
      rules[source] = target;
    }
  }

  deleteRule([_, denyMode]) {
    let rules = this.explicitMappingRules.getValue();
    if (denyMode) {
      rules[this.parent + ":" + this.item.name] = null;
    } else {
      delete rules[this.parent + ":" + this.item.name];
    }
    this.explicitMappingRules.next(rules);
  }

  toggleFiled(v) {
    this.field[v ? "enable" : "disable"]();
  }
}
