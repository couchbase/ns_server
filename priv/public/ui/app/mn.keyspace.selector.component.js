/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {takeUntil, withLatestFrom} from 'rxjs/operators';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnFormService} from './mn.form.service.js';
import template from "./mn.keyspace.selector.html";

export {MnKeyspaceSelectorComponent};

class MnKeyspaceSelectorComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-keyspace-selector",
      template,
      inputs: [
        "service",
        "defaults",
        "customDropdownClass"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush,
      host: {
        '(click)': '$event.stopPropagation()',
      }
    })
  ]}

  static get parameters() { return [
    MnFormService
  ]}

  constructor(mnFormService) {
    super();
    this.form = mnFormService.create(this).setFormGroup({}).hasNoPostRequest();
  }

  ngOnInit() {
    this.defaults && this.service.setKeyspace(this.defaults);

    this.form.submit
      .pipe(withLatestFrom(this.service.stream.step),
            takeUntil(this.mnOnDestroy))
      .subscribe(([item, step]) => {
        this.service.setResultItem(item, step);
      });
  }
}
