/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { Injectable } from "/ui/web_modules/@angular/core.js";
import { HttpClient, HttpParams } from '/ui/web_modules/@angular/common/http.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnPermissions } from '/ui/app/ajs.upgraded.providers.js';
import { switchMap, shareReplay, map } from '/ui/web_modules/rxjs/operators.js';
import { NEVER } from '/ui/web_modules/rxjs.js';
import { is } from '../web_modules/ramda.js';
import { MnHttpRequest } from './mn.http.request.js';

export { MnSettingsAutoCompactionService }

class MnSettingsAutoCompactionService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient,
    MnHelperService,
    MnPermissions
  ]}

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
   * AllowedTimePeriod is added on the basis it's key is
   * present in the payload of the request.
   */
  getSettingsSource(settings) {
    let data = settings.autoCompactionSettings;

    let source = {
      indexCompactionMode: data.indexCompactionMode,
      timePeriodFlag: this.isTimePeriodFlagChecked(data),
      databaseFragmentationThreshold: this.setThresholdGroup(data.databaseFragmentationThreshold),
      viewFragmentationThreshold: this.setThresholdGroup(data.viewFragmentationThreshold),
      indexFragmentationThreshold: data.indexFragmentationThreshold,
      indexCircularCompaction: {
        daysOfWeek: this.mnHelperService.stringToObject(data.indexCircularCompaction.daysOfWeek),
        interval: data.indexCircularCompaction.interval
      },
      parallelDBAndViewCompaction: data.parallelDBAndViewCompaction,
      purgeInterval: settings.purgeInterval,
    };

    if (data.allowedTimePeriod) {
      source.allowedTimePeriod = data.allowedTimePeriod;
    }

    return source;
  }

  isFlagEnabled(value) {
    return Number.isInteger(value);
  }

  maybeDefaultPercentage(value) {
    return Number.isInteger(value) ? value : "";
  }

  maybeDefaultSize(value) {
    return Number.isInteger(value) ? this.mnHelperService.transformBytesToMB(value) : "";
  }

  setThresholdGroup(threshold) {
    return {
      percentage: this.maybeDefaultPercentage(threshold.percentage),
      percentageFlag: this.isFlagEnabled(threshold.percentage),
      size: this.maybeDefaultSize(threshold.size),
      sizeFlag: this.isFlagEnabled(threshold.size)
    };
  }

  isTimePeriodFlagChecked(data) {
    let view = data.viewFragmentationThreshold;
    let database = data.databaseFragmentationThreshold;
    let values = Object.values(view).concat(Object.values(database));

    return data.allowedTimePeriod ? values.some(x => Number.isInteger(x)) : false;
  }
}
