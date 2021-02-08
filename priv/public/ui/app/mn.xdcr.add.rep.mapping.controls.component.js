import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {takeUntil, withLatestFrom, shareReplay} from '/ui/web_modules/rxjs/operators.js';
import {of} from "/ui/web_modules/rxjs.js";
import {MnHelperService} from "./mn.helper.service.js";
import {FormBuilder} from '/ui/web_modules/@angular/forms.js';
import {MnXDCRService, collectionDelimiter} from "./mn.xdcr.service.js";

import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnXDCRAddRepMappingControlsComponent};

class MnXDCRAddRepMappingControlsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-add-rep-mapping-controls",
      templateUrl: "/ui/app/mn.xdcr.add.rep.mapping.controls.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item",
        "keyspace",
        "parent",
        "explicitMappingGroup",
        "explicitMappingRules"
      ]
    })
  ]}


  static get parameters() { return [
    MnHelperService,
    FormBuilder,
    MnXDCRService
  ]}

  constructor(mnHelperService, formBuilder, mnXDCRService) {
    super();
    this.toggler = mnHelperService.createToggle();
    this.filter = mnHelperService.createFilter(this);
    this.mnHelperService = mnHelperService;
    this.formBuilder = formBuilder;
    this.setMappingRule = mnXDCRService.setMappingRule;
  }

  ngOnInit() {
    let isCollection = this.keyspace == "collections";

    if (!this.explicitMappingGroup[this.keyspace][this.parent]) {
      this.explicitMappingGroup[this.keyspace][this.parent] = {
        flags: this.formBuilder.group({}),
        fields: this.formBuilder.group({})
      };
    }

    if (!this.explicitMappingGroup[this.keyspace + "Controls"][this.parent]) {
      let isDisabled = isCollection ?
          !this.explicitMappingGroup.scopes.root.flags.get(this.parent).value : false;
      this.explicitMappingGroup[this.keyspace + "Controls"][this.parent] =
        this.formBuilder.group({
          checkAll: this.formBuilder.control({value: true, disabled: isDisabled}),
          denyMode: this.formBuilder.control({value: true, disabled: isDisabled})
        });
    }

    this.group = this.explicitMappingGroup[this.keyspace][this.parent];
    this.controls = this.explicitMappingGroup[this.keyspace + "Controls"][this.parent];

    this.scopeGroup = isCollection ?
      this.explicitMappingGroup.scopes.root : this.group;
    this.scopeControlsGroup = isCollection ?
      this.explicitMappingGroup.scopesControls.root : this.controls;


    let rawItems = of(isCollection ? this.item.collections : this.item);
    this.filteredItems = rawItems.pipe(this.filter.pipe,
                                       shareReplay({refCount: true, bufferSize: 1}));

    let doSet = isCollection ? this.toggleDenyModeCollections : this.toggleDenyModeScopes;

    this.initialDenyMode = this.controls.get("denyMode").value;
    this.controls.get("checkAll").valueChanges
      .pipe(withLatestFrom(this.filteredItems),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.toggleFilteredItems.bind(this));

    this.controls.get("denyMode").valueChanges
      .pipe(withLatestFrom(rawItems),
            takeUntil(this.mnOnDestroy))
      .subscribe(doSet.bind(this));

    if (!isCollection) {
      this.scopesPaginator =
        this.mnHelperService.createPagenator(this, this.filteredItems, "scopesPage");
    }
  }

  toggleDenyModeScopes([denyMode, items]) {
    let rules = this.explicitMappingRules.getValue();

    items.forEach(item => {
      let collectionGroup = this.explicitMappingGroup.collections[item.name];
      let targetScopeField = this.scopeGroup.fields.get(item.name);
      let sourceScopeField = this.scopeGroup.flags.get(item.name);
      let sourceScope = item.name;
      let targetScope =  targetScopeField ? targetScopeField.value : sourceScope;
      let sourceFlag = sourceScopeField ? sourceScopeField.value : this.initialDenyMode;

      this.setMappingRule(sourceFlag, denyMode, sourceScope,
                          targetScope, sourceScope, targetScope, rules);

      if (!sourceFlag) {
        item.collections.forEach(item => {
          let targetCollField = collectionGroup && collectionGroup.fields.get(item.name);
          let sourceCollection = item.name;
          let source = sourceScope + collectionDelimiter + sourceCollection;
          let targetCollection = targetCollField ? targetCollField.value : sourceCollection;
          let target = targetScope + collectionDelimiter + targetCollection;

          //false, false - means remove rule
          this.setMappingRule(false, false, sourceCollection,
                              targetCollection, source, target, rules);
        });
      } else {
        this.doToggleCollections(item.name, targetScope, rules, item.collections);
      }
    });

    this.explicitMappingRules.next(rules);
  }

  toggleDenyModeCollections([_, items]) {
    let rules = this.explicitMappingRules.getValue();
    let sourceScope = this.parent;
    let targetScope = this.scopeGroup.fields.get(this.parent).value;
    this.doToggleCollections(sourceScope, targetScope, rules, items);
    this.explicitMappingRules.next(rules);
  }

  doToggleCollections(sourceScope, targetScope, rules, collections) {
    let collectionGroup = this.explicitMappingGroup.collections[sourceScope];
    let collectionControls = this.explicitMappingGroup.collectionsControls[sourceScope];
    let collectionDenyMode = collectionControls ? collectionControls.get("denyMode").value:true;
    let scopeDenyMode = this.scopeControlsGroup.get("denyMode").value;

    collections.forEach(item => {
      let thisCollectionField = collectionGroup && collectionGroup.fields.get(item.name);
      let thisCollectionFlag = collectionGroup && collectionGroup.flags.get(item.name);

      let sourceCollection = item.name;
      let source = sourceScope + collectionDelimiter + sourceCollection;
      let targetCollection = thisCollectionField ? thisCollectionField.value : sourceCollection;
      let target = targetScope + collectionDelimiter + targetCollection;

      let actualValue = (thisCollectionFlag ? thisCollectionFlag.value : collectionDenyMode);

      let collectionFlag =
          (!collectionDenyMode && !scopeDenyMode) ?
          (target == source ? false : actualValue) :
          actualValue;

      this.setMappingRule(collectionFlag, collectionDenyMode, sourceCollection,
                          targetCollection, source, target, rules);
    });
  }

  toggleFilteredItems([value, items]) {
    this.group.flags.patchValue(items.reduce((acc, item) => {
      acc[item.name] = value;
      return acc;
    }, {}));
  }

  trackCollectionsBy(_, coll) {
    return coll.uid;
  }
}
