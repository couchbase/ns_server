/*
  Copyright 2021-Present Couchbase, Inc.

  Use of this software is governed by the Business Source License included in
  the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
  file, in accordance with the Business Source License, use of this software
  will be governed by the Apache License, Version 2.0, included in the file
  licenses/APL2.txt.
*/
import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnLogsListService } from './mn.logs.list.service.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { Subject } from 'rxjs';
import {
  pluck,
  filter,
  shareReplay,
  map,
  takeUntil,
  distinctUntilChanged,
} from 'rxjs/operators';
import { MnMainSpinner } from './components/directives/mn_main_spinner.jsx';
import { MnInputFilter } from './mn.input.filter.component.jsx';
import { MnTextExpander } from './mn.text.expander.component.jsx';
import { DatePipe } from '@angular/common';

class MnLogsListComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      logs: null,
      sorterState: null,
    };
  }

  componentDidMount() {
    this.textLimit = 1000;
    this.sorter = MnHelperService.createSorter('tstamp', true);
    this.filter = MnHelperService.createFilter(
      this,
      ['text', 'module', 'code', 'node', 'prettyTime'],
      true
    );
    this.sorterState = this.sorter.state;
    MnHelperReactService.async(this, 'sorterState');

    this.logs = MnLogsListService.stream.logs.pipe(
      pluck('list'),
      filter((logs) => !!logs),
      map(this.addPrettyTime.bind(this)),
      this.filter.pipe,
      this.sorter.pipe,
      shareReplay({ refCount: true, bufferSize: 1 })
    );
    MnHelperReactService.async(this, 'logs');

    this.doFocusFilter = new Subject();
    this.doFocusFilter.next('filter');
  }

  trackByMethod(index, log) {
    return (
      log.shortText +
      log.code +
      log.module +
      log.node +
      log.tstamp +
      log.serverTime +
      log.type +
      log.text
    );
  }

  addPrettyTime(logs) {
    logs.forEach(
      (log) =>
        (log.prettyTime =
          new DatePipe().transform(
            log.serverTime,
            'mediumTime',
            'UTC',
            'en-US'
          ) +
          ' ' +
          new DatePipe().transform(log.serverTime, 'd MMM, y', 'UTC', 'en-US'))
    );
    return logs;
  }

  formatCode(code) {
    return code.toString().padStart(3, '0');
  }

  render() {
    const { logs, sorterState } = this.state;

    if (!this.filter) {
      return <MnMainSpinner mnSpinnerValue={true} />;
    }

    return (
      <div>
        <MnMainSpinner mnSpinnerValue={logs === null} />
        <div className="fix-width-4-5">
          <MnInputFilter
            className="row flex-left margin-bottom-half filter-log"
            group={this.filter.group}
            mnFocus={this.doFocusFilter}
            mnName="filter"
            mnPlaceholder="filter logs..."
            mnClearDisabled={false}
          />
        </div>

        <div className="cbui-table">
          <div className="cbui-table-header padding-left resp-hide-sml">
            <span className="cbui-table-cell flex-grow-3">event</span>
            <span className="cbui-table-cell">
              <span
                className={`sorter ${sorterState?.[0] === 'module' ? 'dynamic-active' : ''} 
                           ${sorterState?.[1] ? 'dynamic-inverted' : ''}`}
                onClick={() => this.sorter.click.next('module')}
              >
                module code
              </span>
            </span>
            <span className="cbui-table-cell">
              <span
                className={`sorter ${sorterState?.[0] === 'node' ? 'dynamic-active' : ''} 
                           ${sorterState?.[1] ? 'dynamic-inverted' : ''}`}
                onClick={() => this.sorter.click.next('node')}
              >
                server node
              </span>
            </span>
            <span className="cbui-table-cell flex-grow-1-5">
              <span
                className={`sorter ${sorterState?.[0] === 'tstamp' ? 'dynamic-active' : ''} 
                           ${sorterState?.[1] ? 'dynamic-inverted' : ''}`}
                onClick={() => this.sorter.click.next('tstamp')}
              >
                time
              </span>
            </span>
          </div>

          {logs?.map((log, index) => (
            <section key={this.trackByMethod(index, log)}>
              <div className="cbui-tablerow items-top resp-sml">
                <span className="cbui-table-cell flex-grow-3 min-width-zero resp-sml">
                  <MnTextExpander text={log.text} limit={this.textLimit} />
                </span>
                <span
                  className="cbui-table-cell resp-sml"
                  title={`${log.module} ${this.formatCode(log.code)}`}
                >
                  {log.module} {this.formatCode(log.code)}
                </span>
                <span className="cbui-table-cell cursor-pointer resp-sml">
                  <span title={log.node}>{log.node}</span>
                </span>
                <span className="cbui-table-cell flex-grow-1-5 wrap resp-sml">
                  <span className="semi-bold nowrap margin-right-half">
                    {new Date(log.serverTime).toLocaleTimeString('en-US', {
                      timeZone: 'UTC',
                    })}
                  </span>
                  <span className="nowrap">
                    {new Date(log.serverTime).toLocaleDateString('en-US', {
                      day: 'numeric',
                      month: 'short',
                      year: 'numeric',
                      timeZone: 'UTC',
                    })}
                  </span>
                </span>
              </div>
            </section>
          ))}
        </div>
      </div>
    );
  }
}

export { MnLogsListComponent };
