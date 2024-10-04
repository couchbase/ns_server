/*
Copyright 2024-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core'
import {takeUntil, shareReplay} from 'rxjs/operators';
import {of} from 'rxjs';
import {FormBuilder} from '@angular/forms';

import {MnHelperService} from './mn.helper.service.js';
import {MnXDCRService} from './mn.xdcr.service.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import template from "./mn.xdcr.conflict.log.mapping.controls.html";

export {MnXDCRConflictLogMappingControlsComponent};

class MnXDCRConflictLogMappingControlsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-conflict-log-mapping-controls",
      template,
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item",
        "keyspace",
        "parent",
        "mappingGroup",
        "mappingRules",
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
    this.isCollection = this.keyspace == "collections";
    if (this.parent === 'root') {
      this.group = this.mappingGroup.rootControls;
      this.controls = this.mappingGroup.rootControls.controls;
    } else {
      this.group = this.mappingGroup.ruleControls.scopes[this.item.name];
      this.controls = this.mappingGroup.ruleControls.scopes[this.item.name].collections;
    }
    this.scopeGroup = this.isCollection ?
      this.mappingGroup.ruleControls.scopes[this.item.name] : this.group;

    let rawItems = of(this.isCollection ? this.item.collections : this.item);

    this.filteredItems = rawItems.pipe(this.filter.pipe,
                                       shareReplay({refCount: true, bufferSize: 1}));

    if (this.parent === 'root') {
      this.group.get("root_scopes_checkAll").valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.doRootToggle.bind(this));

      this.group.get("root_bucket").valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.setRootBucket.bind(this));

      this.group.get("root_collection").valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.setRootCollection.bind(this));
    }

    if (!this.isCollection) {
      this.scopesPaginator =
        this.mnHelperService.createPagenator(this, this.filteredItems, "scopesPage");
    }
  }

  doRootToggle(checkAll) {
    let rules = this.mappingRules.getValue();
    let rootBucketField = this.group.get('root_bucket');
    let rootCollectionField = this.group.get('root_collection');
    rules.bucket = checkAll ? rootBucketField.value : '';
    rules.collection = checkAll ? rootCollectionField.value: '';
    rootBucketField.patchValue(rules.bucket);
    rootCollectionField.patchValue(rules.collection);
    let action = checkAll ? 'enable' : 'disable';
    rootBucketField[action]({emitEvent: false});
    rootCollectionField[action]({emitEvent: false});
    this.mappingRules.next(rules);
  }

  setRootBucket(value) {
    let rules = this.mappingRules.getValue();
    rules.bucket = value;
    this.mappingRules.next(rules);
  }

  setRootCollection(value) {
    let rules = this.mappingRules.getValue();
    rules.collection = value;
    this.mappingRules.next(rules);
  }

  trackCollectionsBy(_, coll) {
    return coll.uid;
  }
}
