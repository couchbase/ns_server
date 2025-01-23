/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {HttpParams} from '@angular/common/http';
import {HttpClient} from './mn.http.client.js';
import {NEVER} from 'rxjs';
import {switchMap, shareReplay, map} from 'rxjs/operators';
import {clone, is} from 'ramda';

import mnPermissions from './components/mn_permissions.js';
import {MnHelperService} from './mn.helper.service.js';
import {MnHttpRequest} from './mn.http.request.js';

class MnSettingsAutoCompactionServiceClass {
  constructor(http, mnHelperService, permissions) {
    this.http = http;
    this.stream = {};
    this.mnHelperService = mnHelperService;
    this.permissions = permissions.stream;
    this.flattenData = this.flattenData.bind(this);

    this.stream.getAutoCompaction = this.permissions
      .pipe(switchMap(permissions =>
        permissions.cluster.settings.autocompaction.read ? this.getAutoCompaction() : NEVER),
            shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getIndexSettings = this.permissions
      .pipe(switchMap(permissions =>
        permissions.cluster.settings.indexes.read ? this.getIndexSettings() : NEVER),
            shareReplay({refCount: true, bufferSize: 1}));

    this.stream.isMemoryOptimized = this.stream.getIndexSettings
      .pipe(map(value => value.storageMode === "memory_optimized"));

    this.stream.postAutoCompaction =
      new MnHttpRequest(this.postAutoCompaction(false).bind(this))
      .addSuccess()
      .addError();

    this.stream.postAutoCompactionValidation =
      new MnHttpRequest(this.postAutoCompaction(true).bind(this))
      .addSuccess()
      .addError();

    this.stream.settingsSource = this.stream.getAutoCompaction
      .pipe(map(this.getSettingsSource.bind(this)));
  }

  getAutoCompaction() {
    return this.http.get('/settings/autoCompaction');
  }

  postAutoCompaction(validate) {
    return (data) => {
      return this.http.post('/controller/setAutoCompaction', data, {
        params: new HttpParams().set("just_validate", validate ? 1 : 0)
      });
    }
  }

  getIndexSettings() {
    return this.http.get('/settings/indexes');
  }

  flattenData(obj, path = [], result = {}) {
    Object.keys(obj).forEach(k => {
      if (is(Object, obj[k])) {
        this.flattenData(obj[k], [...path, k], result);
      } else {
        let resultKey = [...path, k].reduce((acc, s, i) => acc + (i ? `[${s}]`: s));
        result[resultKey] = obj[k];
      }
    })

    return result;
  }

  /**
   * Sets the initial values of the auto compaction settings form.
   * Fragmentation and AllowedTimePeriod keys are added on the basis
   * they are present in the payload of the request.
   */
  getSettingsSource(settings) {
    let data = settings.autoCompactionSettings;

    let source = {
      indexCompactionMode: data.indexCompactionMode,
      timePeriodFlag: !!data.allowedTimePeriod,
      parallelDBAndViewCompaction: data.parallelDBAndViewCompaction,
      purgeInterval: settings.purgeInterval,
    };

    if (data.databaseFragmentationThreshold) {
      source.databaseFragmentationThreshold = this.setThresholdGroup(data.databaseFragmentationThreshold);
    }

    if (data.viewFragmentationThreshold) {
      source.viewFragmentationThreshold = this.setThresholdGroup(data.viewFragmentationThreshold);
    }

    if (data.indexFragmentationThreshold) {
      source.indexFragmentationThreshold = data.indexFragmentationThreshold;
    }

    if (data.indexCircularCompaction) {
      source.indexCircularCompaction = {
        daysOfWeek: this.mnHelperService.stringToObject(data.indexCircularCompaction.daysOfWeek),
        interval: data.indexCircularCompaction.interval
      }
    }

    if (data.allowedTimePeriod) {
      source.allowedTimePeriod = data.allowedTimePeriod;
    }

    source.magmaFragmentationPercentage = data.magmaFragmentationPercentage;

    return source;
  }

  getAutoCompactionData(group) {
    let values = clone(group.value);

    if (values.databaseFragmentationThreshold) {
      values.databaseFragmentationThreshold.size = Number.isFinite(values.databaseFragmentationThreshold.size) ?
        this.mnHelperService.transformMBToBytes(values.databaseFragmentationThreshold.size) :
        "undefined";

      values.databaseFragmentationThreshold.percentage =  Number.isFinite(values.databaseFragmentationThreshold.percentage) ?
        values.databaseFragmentationThreshold.percentage :
        "undefined";

      delete values.databaseFragmentationThreshold.sizeFlag;
      delete values.databaseFragmentationThreshold.percentageFlag;
    }

    if (values.viewFragmentationThreshold) {
      values.viewFragmentationThreshold.size = Number.isFinite(values.viewFragmentationThreshold.size) ?
        this.mnHelperService.transformMBToBytes(values.viewFragmentationThreshold.size) :
        "undefined";

      values.viewFragmentationThreshold.percentage = Number.isFinite(values.viewFragmentationThreshold.percentage) ?
        values.viewFragmentationThreshold.percentage :
        "undefined";

      delete values.viewFragmentationThreshold.sizeFlag;
      delete values.viewFragmentationThreshold.percentageFlag;
    }

    values.purgeInterval = Number(values.purgeInterval);
    values.magmaFragmentationPercentage = Number(values.magmaFragmentationPercentage);

    delete values.timePeriodFlag;

    return this.flattenData(values);
  }

  isFlagEnabled(value) {
    return Number.isInteger(value);
  }

  maybeDefaultPercentage(value) {
    return Number.isFinite(value) ? value : "";
  }

  maybeDefaultSize(value) {
    return Number.isFinite(value) ? this.mnHelperService.transformBytesToMB(value) : "";
  }

  setThresholdGroup(threshold) {
    return {
      percentage: this.maybeDefaultPercentage(threshold.percentage),
      percentageFlag: this.isFlagEnabled(threshold.percentage),
      size: this.maybeDefaultSize(threshold.size),
      sizeFlag: this.isFlagEnabled(threshold.size)
    };
  }
}

const MnSettingsAutoCompactionService = new MnSettingsAutoCompactionServiceClass(HttpClient, MnHelperService, mnPermissions);
export {MnSettingsAutoCompactionService};
