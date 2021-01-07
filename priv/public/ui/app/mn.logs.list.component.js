/*
  Copyright 2021-Present Couchbase, Inc.

  Use of this software is governed by the Business Source License included in
  the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
  file, in accordance with the Business Source License, use of this software will
  be governed by the Apache License, Version 2.0, included in the file
  licenses/APL2.txt.
*/

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {pluck, filter, shareReplay, map} from "/ui/web_modules/rxjs/operators.js";
import {MnLogsListService} from './mn.logs.list.service.js';
import {MnHelperService} from './mn.helper.service.js';
import {DatePipe} from '/ui/web_modules/@angular/common.js';

export {MnLogsListComponent};

class MnLogsListComponent extends MnLifeCycleHooksToStream {

  static get annotations() {
    return [
      new Component({
        templateUrl: "/ui/app/mn.logs.list.html",
        changeDetection: ChangeDetectionStrategy.OnPush
      })
  ]}

  static get parameters() { return [
    MnLogsListService,
    MnHelperService,
    DatePipe
  ]}

  constructor(MnLogsService, MnHelperService, DatePipe) {
    super();

    this.textLimit = 1000;
    this.sorter = MnHelperService.createSorter('tstamp', true);
    this.filter = MnHelperService.createFilter(this,
                                               ['text', 'module', 'code', 'node', 'prettyTime'],
                                               true);

    this.logs = MnLogsService.stream.logs
      .pipe(pluck('list'),
            filter(logs => !!logs),
            map(this.addPrettyTime.bind(this)),
            this.filter.pipe,
            this.sorter.pipe,
            shareReplay({refCount: true, bufferSize: 1}));
  }

  trackByMethod(index, log) {
    return log.shortText +
           log.code +
           log.module +
           log.node +
           log.tstamp +
           log.serverTime +
           log.type;
  }

  addPrettyTime(logs) {
    let datePipe = new DatePipe();
    logs.forEach(log =>
                 log.prettyTime = datePipe.transform(log.serverTime, 'mediumTime', 'UTC', 'en-US') +
                                  " " +
                                  datePipe.transform(log.serverTime, 'd MMM, y', 'UTC', 'en-US'));
    return logs;
  }
}
