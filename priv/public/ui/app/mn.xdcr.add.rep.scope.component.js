import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {takeUntil, pluck, startWith, withLatestFrom} from '/ui/web_modules/rxjs/operators.js';
import {Subject, merge} from "/ui/web_modules/rxjs.js";
import {MnHelperService} from "./mn.helper.service.js";
import {FormBuilder} from '/ui/web_modules/@angular/forms.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnXDCRAddRepScopeComponent};

class MnXDCRAddRepScopeComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-add-rep-scope",
      templateUrl: "/ui/app/mn.xdcr.add.rep.scope.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item",
        "group",
        "explicitMappingRules"
      ]
    })
  ]}


  static get parameters() { return [
    MnHelperService,
    FormBuilder
  ]}

  constructor(mnHelperService, formBuilder) {
    super();
    this.toggler = mnHelperService.createToggle();
    this.filter = mnHelperService.createFilter("name");
    this.formBuilder = formBuilder;

    this.collections =
      this.mnOnChanges.pipe(pluck("item", "currentValue", "collections"),
                            this.filter.pipe);
  }

  ngOnInit() {
    let name = this.item.name;
    if (!this.group.collections[name]) {
      this.group.collections[name] = {
        flags: this.formBuilder.group({}),
        fields: this.formBuilder.group({})
      };
    }

    if (!this.group.collectionsControls[name]) {
      this.group.collectionsControls[name] = this.formBuilder.group({
        checkAll: this.formBuilder.control({value: true, disabled: true}),
        denyMode: this.formBuilder.control({value: true, disabled: true})
      });
    }
    if (!this.group.scopes.flags.get(name)) {
      this.group.scopes.flags
        .addControl(name, this.formBuilder.control({value: false, disabled: false}));
      this.group.scopes.fields
        .addControl(name, this.formBuilder.control({value: name, disabled: false}));
    }

    this.childGroup = this.group.collections[name];
    this.controls = this.group.collectionsControls[name];
    this.flag = this.group.scopes.flags.get(name);
    this.field = this.group.scopes.fields.get(name);

    this.filter.group.get("value").valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(v => {
        this.controls.get("denyMode")[!!v ? "disable" : "enable"]();
      });

    this.controls.get("checkAll").valueChanges
      .pipe(withLatestFrom(this.collections),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.toggleFilteredCollections.bind(this));

    this.flag.valueChanges
      .pipe(startWith(this.flag.value),
            takeUntil(this.mnOnDestroy))
      .subscribe(v => {
        this.childGroup.fields[v ? "enable" : "disable"]({emitEvent: v});
        this.childGroup.flags[v ? "enable" : "disable"]({emitEvent: v});
        this.controls[v ? "enable" : "disable"]({emitEvent: false});
      });

    this.denyModeControl = this.controls.get("denyMode");
    let denyModeStream =
        this.denyModeControl.valueChanges.pipe(startWith(this.denyModeControl.value));

    merge(this.flag.valueChanges,
          this.field.valueChanges,
          this.childGroup.flags.valueChanges,
          denyModeStream)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.setScopeRule.bind(this));
  }

  setScopeRule() {
    let rules = this.explicitMappingRules.getValue();
    if (this.flag.value) {
      if (!this.denyModeControl.value) {
        delete rules[this.item.name];
      } else {
        rules[this.item.name] = this.field.value;
      }
    } else {
      delete rules[this.item.name];
    }
    this.explicitMappingRules.next(rules);
  }

  toggleFilteredCollections([value, collections]) {
    this.childGroup.flags.patchValue(collections.reduce((acc, item) => {
      acc[item.name] = value;
      return acc;
    }, {}));
  }

  trackCollectionsBy(_, coll) {
    return coll.uid;
  }
}
