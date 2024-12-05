/*
Copyright 2024-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core'

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnHelperService} from "./mn.helper.service.js";
import template from "./mn.xdcr.conflict.log.scope.html";

export {MnXDCRConflictLogScopeComponent};

class MnXDCRConflictLogScopeComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-conflict-log-scope",
      template,
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item",
        "mappingGroup",
        "mappingRules",
      ]
    })
  ]}


  static get parameters() { return [
    MnHelperService
  ]}

  constructor(mnHelperService) {
    super();
    this.toggler = mnHelperService.createToggle();
  }
}
