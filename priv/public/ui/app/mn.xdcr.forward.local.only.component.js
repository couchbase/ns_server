/*
Copyright 2026-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {merge} from 'rxjs';
import {map, mapTo, startWith} from 'rxjs/operators';

import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {MnPoolsService} from "./mn.pools.service.js";
import {MnAdminService} from "./mn.admin.service.js";
import {MnXDCRService} from "./mn.xdcr.service.js";

import template from "./mn.xdcr.forward.local.only.html";

export {MnXDCRForwardLocalOnlyComponent};

class MnXDCRForwardLocalOnlyComponent extends MnLifeCycleHooksToStream {
  static get annotations() {
    return [
      new Component({
        selector: "mn-xdcr-forward-local-only",
        template,
        changeDetection: ChangeDetectionStrategy.OnPush,
        inputs: [
          "group"
        ]
      })
    ]
  }

  static get parameters() {
    return [
      MnPoolsService,
      MnAdminService,
      MnXDCRService
    ]
  }

  constructor(mnPoolsService, mnAdminService, mnXDCRService) {
    super();

    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.compatVersion80 = mnAdminService.stream.compatVersion80;

    let postCreateReplication = mnXDCRService.stream.postCreateReplication;
    let postSettingsReplications = mnXDCRService.stream.postSettingsReplications;
    let postSettingsReplicationsValidation = mnXDCRService.stream.postSettingsReplicationsValidation;
    let postCreateReplicationValidation = mnXDCRService.stream.postCreateReplicationValidation;

    this.error = merge(
      postCreateReplication.error.pipe(map(extractForwardLocalOnlyError)),
      postSettingsReplications.error.pipe(map(extractForwardLocalOnlyError)),
      postSettingsReplicationsValidation.error.pipe(map(extractForwardLocalOnlyError)),
      postCreateReplicationValidation.error.pipe(map(extractForwardLocalOnlyError)),
      postCreateReplication.success.pipe(mapTo(null)),
      postSettingsReplications.success.pipe(mapTo(null)),
      postSettingsReplicationsValidation.success.pipe(mapTo(null)),
      postCreateReplicationValidation.success.pipe(mapTo(null)));

    function extractForwardLocalOnlyError(error) {
      return error && error.forwardLocalOnly ? {forwardLocalOnly: error.forwardLocalOnly} : null;
    }
  }

  ngOnInit() {
    let forwardLocalOnly = this.group.get('forwardLocalOnly');
    this.isInitialChecked = forwardLocalOnly.value;
    this.showWarning = forwardLocalOnly.valueChanges.pipe(
      startWith(forwardLocalOnly.value),
      map((value) => {
        if (value && !forwardLocalOnly.dirty) {
          this.isInitialChecked = true;
        }
        return !this.isInitialChecked && value && forwardLocalOnly.dirty;
      }));
  }
}
