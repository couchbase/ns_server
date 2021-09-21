/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {map} from 'rxjs/operators';
import {combineLatest} from 'rxjs';

import {MnPoolsService} from './mn.pools.service.js';
import {MnSettingsAutoCompactionService} from './mn.settings.auto.compaction.service.js';
import {MnHelperService} from './mn.helper.service.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnSettingsAutoCompactionFormComponent};

class MnSettingsAutoCompactionFormComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-auto-compaction-form",
      templateUrl: "app/mn.settings.auto.compaction.form.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        'mnGroup',
        'mnErrors',
        'isBucketSettings'
      ]
    })
  ]}

  static get parameters() { return [
    MnPoolsService,
    MnSettingsAutoCompactionService,
    MnHelperService
  ] }

  constructor(mnPoolsService, mnSettingsAutoCompactionService, mnHelperService) {
    super();

    this.storageMode = mnSettingsAutoCompactionService.stream.storageMode;
    this.daysOfWeek = mnHelperService.daysOfWeek;
    this.postRequest = mnSettingsAutoCompactionService.stream.postAutoCompaction;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.isMemoryOptimized = mnSettingsAutoCompactionService.stream.isMemoryOptimized;

    this.showIndexFragmentation =
      combineLatest(this.isMemoryOptimized,
                    this.isEnterprise)
      .pipe(map(this.showIndexFragmentation.bind(this)));

    this.showGsiWarning =
      combineLatest(this.isMemoryOptimized,
                    this.isEnterprise)
      .pipe(map(this.showGsiWarning.bind(this)));
  }

  ngOnInit() {
    this.purgeIntervalIsOne =
      this.mnGroup.get('purgeInterval').valueChanges
        .pipe(map(interval => interval == 1 ? "" : "s"));
  }

  showGsiWarning([isMemoryOptimized, isEnterprise]) {
    return isMemoryOptimized || isEnterprise;
  }

  showIndexFragmentation([isMemoryOptimized, isEnterprise]) {
    return !isMemoryOptimized && !isEnterprise && !this.isBucketSettings;
  }
}
