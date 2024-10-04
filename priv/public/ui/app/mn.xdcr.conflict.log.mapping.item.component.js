/*
Copyright 2024-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core'
import {takeUntil} from 'rxjs/operators';
import {FormBuilder} from '@angular/forms';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnXDCRService, collectionDelimiter} from "./mn.xdcr.service.js";
import template from "./mn.xdcr.conflict.log.mapping.item.html";

export {MnXDCRConflictLogMappingItemComponent};

class MnXDCRConflictLogMappingItemComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-conflict-log-mapping-item",
      template,
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item",
        "mappingGroup",
        "parent",
        "mappingRules",
        "keyspace"
      ]
    })
  ]}

  static get parameters() { return [
    FormBuilder,
    MnXDCRService
  ]}

  constructor(formBuilder, mnXDCRService) {
    super();
    this.formBuilder = formBuilder;
    this.setMappingRule = mnXDCRService.setMappingRule;
  }

  ngOnInit() {
    this.isCollection = this.keyspace == "collections";
    if (this.parent === 'root') {
      this.group = this.mappingGroup.rootControls;
    } else {
      if (this.isCollection) {
        this.group = this.mappingGroup.ruleControls.scopes[this.parent].collections[this.item.name];
      } else {
        this.group = this.mappingGroup.ruleControls.scopes[this.parent];
      }
    }
    this.controls = this.group.controls;

    this.group.get(`${this.item.name}_${this.keyspace}_checkAll`).valueChanges.pipe(takeUntil(this.mnOnDestroy)).subscribe((value) => this.enableRule(value));
    this.group.get('bucket').valueChanges.pipe(takeUntil(this.mnOnDestroy)).subscribe((value) => this.setRule(value, 'bucket'));
    this.group.get('collection').valueChanges.pipe(takeUntil(this.mnOnDestroy)).subscribe((value) => this.setRule(value, 'collection'));

    this.mappingRules.pipe(takeUntil(this.mnOnDestroy)).subscribe(this.updateCheckboxes.bind(this));
  }

  setRule(value, property) {
    let rules = this.mappingRules.getValue();
    rules.loggingRules = rules.loggingRules || {};
    const ruleName = this.getRuleName();
    rules.loggingRules[ruleName] = rules.loggingRules[ruleName] || {};
    rules.loggingRules[ruleName][property] = value;
    this.mappingRules.next(rules);
  }

  deleteRule() {
    let rules = this.mappingRules.getValue();
    rules.loggingRules = rules.loggingRules || {};
    delete rules.loggingRules[this.getRuleName()];
    this.mappingRules.next(rules);
  }

  enableRule(checked) {
    this.group.get('bucket')[checked ? "enable" : "disable"]({emitEvent: false});
    this.group.get('collection')[checked ? "enable" : "disable"]({emitEvent: false});

    if (checked) {
      let defaultRule = this.getDefaultConflictLogRule();
      this.setRule(defaultRule.bucket, 'bucket');
      this.group.get('bucket').patchValue(defaultRule.bucket);
      this.setRule(defaultRule.collection, 'collection');
      this.group.get('collection').patchValue(defaultRule.collection);
    } else {
      this.group.get('bucket').patchValue('');
      this.group.get('collection').patchValue('');
      this.deleteRule();
    }

    // select/unselect the collections
    let collections = this.group.collections;
    (Object.keys(collections || [])).forEach(collection => {
      collections[collection].get(`${collection}_collections_checkAll`).patchValue(checked);
    });
  }

  hasRule() {
    let rules = this.mappingRules.getValue();
    rules.loggingRules = rules.loggingRules || {};
    return rules.loggingRules[this.getRuleName()];
  }

  getDefaultConflictLogRule() {
    const rules = this.mappingRules.getValue();
    const rootValues = {bucket: rules.bucket || '', collection: rules.collection || ''};
    if (rules.loggingRules && this.isCollection) {
      const parentRule = rules.loggingRules[this.parent];
      return parentRule ? {bucket: parentRule.bucket, collection: parentRule.collection} : rootValues;
    }
    return rootValues;
  }

  getRuleName() {
    if (this.isCollection) {
      return `${this.parent}${collectionDelimiter}${this.item.name}`;
    }
    return this.item.name;
  }

  updateCheckboxes() {
    const currentRule = this.hasRule();
    this.group.get(`${this.item.name}_${this.keyspace}_checkAll`).patchValue(!!currentRule, {emitEvent: false});
  }
}
