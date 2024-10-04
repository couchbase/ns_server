/*
Copyright 2024-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {map} from 'rxjs/operators';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {collectionDelimiter} from './mn.xdcr.service.js';
import template from "./mn.xdcr.conflict.log.mapping.rules.html";

export {MnXDCRConflictLogMappingRulesComponent};

class MnXDCRConflictLogMappingRulesComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-conflict-log-mapping-rules",
      template,
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "isEditMode",
        "mappingRules",
        "mappingGroup"
      ]
    })
  ]}

  constructor() {
    super();
  }

  ngOnInit() {
    let kvToArray = (rules) => {
      const rulesToDisplay = [];
      if (rules.bucket || rules.collection) {
        rulesToDisplay.push(['All Conflicts', `${rules['bucket'] || ''}${collectionDelimiter}${rules['collection'] || ''}`]);
      }

      Object.keys(rules?.loggingRules || {}).forEach(rule => {
        const target = rules.loggingRules[rule];
        if (target) {
          if (target.bucket || target.collection) {
            rulesToDisplay.push([rule, `${target.bucket || ''}${collectionDelimiter}${target.collection || ''}`]);
          } else {
            // target defaults to parent target (scope or root)
            if (rule.includes(collectionDelimiter)) {
              const scope = rule.split(collectionDelimiter)[0];
              const scopeTarget = rules.loggingRules[scope];
              if (scopeTarget) {
                if (scopeTarget.bucket || scopeTarget.collection) {
                  rulesToDisplay.push([rule, `${scopeTarget.bucket || ''}${collectionDelimiter}${scopeTarget.collection || ''}`]);
                } else {
                  rulesToDisplay.push([rule, `${rules['bucket'] || ''}${collectionDelimiter}${rules['collection'] || ''}`]);
                }
              }
            } else {
              rulesToDisplay.push([rule, `${rules['bucket'] || ''}${collectionDelimiter}${rules['collection'] || ''}`]);
            }
          }
        }
      });
      return rulesToDisplay;
    };

    this.mappingRulesKeys = this.mappingRules.pipe(map(kvToArray));
  }

  deleteRule(key) {
    let rules = this.mappingRules.getValue();
    if (key === 'All Conflicts') {
      rules.bucket = "";
      rules.collection = "";
      this.mappingGroup.rootControls.get("root_scopes_checkAll").patchValue(false);
    } else {
      if (this.mappingGroup.ruleControls[key]) {
        this.mappingGroup.ruleControls[key].get("checkAll").patchValue(false);
        this.mappingGroup.ruleControls[key].get("bucket").patchValue('');
        this.mappingGroup.ruleControls[key].get("collection").patchValue('');
      }
      delete rules.loggingRules[key];
    }
    this.mappingRules.next(rules);
  }
}
