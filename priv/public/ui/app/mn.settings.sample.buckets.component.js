/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {map, takeUntil, startWith, pairwise, shareReplay} from 'rxjs/operators';
import {FormControl} from '@angular/forms';
import {combineLatest} from 'rxjs';

import {MnFormService} from './mn.form.service.js';
import {MnAdminService} from './mn.admin.service.js';
import {MnBucketsService} from './mn.buckets.service.js';
import {MnSettingsSampleBucketsService} from './mn.settings.sample.buckets.service.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';

export {MnSettingsSampleBucketsComponent};

class MnSettingsSampleBucketsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "app/mn.settings.sample.buckets.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnFormService,
    MnAdminService,
    MnBucketsService,
    MnSettingsSampleBucketsService
  ]}

  constructor(mnFormService, mnAdminService, mnBucketsService, mnSettingsSampleBucketsService) {
    super();

    this.getSampleBuckets = mnSettingsSampleBucketsService.stream.getSampleBuckets;
    this.sampleBucketsGroupByName = mnSettingsSampleBucketsService.stream.sampleBucketsGroupByName;
    this.isRebalancing = mnAdminService.stream.isRebalancing;
    this.maxBucketCount = mnAdminService.stream.maxBucketCount;
    this.postRequest = mnSettingsSampleBucketsService.stream.installSampleBuckets;
    this.compatVersion70 = mnAdminService.stream.compatVersion70;

    this.form = mnFormService.create(this)
      .setFormGroup({})
      .setPackPipe(map(this.getPackedData.bind(this)))
      .setPostRequest(this.postRequest)
      .successMessage("Task added successfully!")
      .clearErrors()
      .showGlobalSpinner();

    this.getSampleBuckets
      .pipe(startWith(null),
            pairwise(),
            takeUntil(this.mnOnDestroy))
      .subscribe(this.addFormControls.bind(this));

    this.indexQueryNodes = mnAdminService.stream.allActiveNodes
      .pipe(map(this.areThereIndexQueryNodes.bind(this)));

    this.selectedQuotas =
      combineLatest(this.form.group.valueChanges,
                    this.sampleBucketsGroupByName)
      .pipe(map(this.getSelectedQuotas.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.maxBucketsExceeded =
      combineLatest(mnBucketsService.stream.getBuckets,
                    mnAdminService.stream.maxBucketCount,
                    this.selectedQuotas)
      .pipe(map(([existingBuckets, maximumBuckets, selected]) =>
        (existingBuckets.length + selected.length) > maximumBuckets),
            shareReplay({refCount: true, bufferSize: 1}));

    this.maxQuotaExceeded =
      combineLatest(mnAdminService.stream.getPoolsDefault,
                    mnAdminService.stream.getNodes,
                    this.selectedQuotas)
      .pipe(map(this.getQuotaExceeded.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.bucketNotSelected = this.form.group.valueChanges
      .pipe(startWith(this.form.group.value),
            map(values => !Object.values(values).some(v => v)));

    this.isNotCompatibleVersion = this.compatVersion70
      .pipe(map(r => !r));

    this.isDisabled =
      combineLatest(this.bucketNotSelected,
                    this.isRebalancing,
                    this.maxQuotaExceeded,
                    this.maxBucketsExceeded,
                    this.isNotCompatibleVersion)
      .pipe(map(conditions => conditions.every(c => !c)));
  }

  addFormControls([oldBuckets, buckets]) {
    buckets.forEach((bucket, index) => {
      let bucketControl = this.form.group.get(bucket.name);
      if (bucketControl) {
        bucketControl[bucket.installed ? 'disable' : 'enable']();
        if (bucket.installed != oldBuckets[index].installed) {
          bucketControl.patchValue(bucket.installed);
        }
      } else {
        this.form.group.addControl(bucket.name, new FormControl({
          value: bucket.installed,
          disabled: bucket.installed
        }));
      }
    });
  }

  getQuotaExceeded([poolsDefault, servers, selectedQuotas]) {
    let quotaNeeded = selectedQuotas.reduce((acc, val) => (acc + val), 0) * servers.length;
    let { quotaTotal, quotaUsed } = poolsDefault.storageTotals.ram;

    if (quotaNeeded >= (quotaTotal - quotaUsed)) {
      return Math.ceil(quotaNeeded - (quotaTotal - quotaUsed)) / 1024 / 1024 / servers.length
    }

    return false;
  }

  areThereIndexQueryNodes(nodes) {
    return !!nodes.filter(node => (["index", "n1ql"]
                            .some(service => node.services.includes(service)))).length;
  }

  getSelectedQuotas([group, sampleBuckets]) {
    return Object.keys(group)
                 .filter(k => group[k])
                 .map(val => sampleBuckets[val][0].quotaNeeded);
  }

  getPackedData() {
    return Object.keys(this.form.group.value).reduce((acc, val) => {
      if (this.form.group.value[val]) {
        acc.push(val)
      }
      return acc;
    }, [])
  }
}
