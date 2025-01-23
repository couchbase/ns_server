/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {FormBuilder} from 'react-reactive-form';
import {UIRouter}  from "mn.react.router";
import {BehaviorSubject, Subject} from 'rxjs';
import {takeUntil, filter} from 'rxjs/operators';
import mitt from 'mitt';

class MnHelperReactServiceClass {
  mnGlobalSpinnerFlag = new BehaviorSubject(false);
  tasks = new BehaviorSubject(null);
  rootScopeEmitter = mitt();
  id() {
    return `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`
  }
  async(component, field) {
    component[field]
      .pipe(takeUntil(component.mnOnDestroy))
      .subscribe((value) => {
        component.setState({ [field]: value });
      });
  }
  mnFocus(component) {
    component.focusFieldSubject
      .pipe(
        filter((value) => {
          return (typeof value === "string") ? value === component.mnName : value
        }),
        takeUntil(component.mnOnDestroy))
      .subscribe(() => {
        setTimeout(() => component.input.focus(), 0);
      });
  }
  valueChanges(reactReactiveFormValueChanges) {
    const valueChanges = new Subject();
    reactReactiveFormValueChanges.subscribe(value => {
      valueChanges.next(value);
    });
    return valueChanges;
  }
}

const MnHelperReactService = new MnHelperReactServiceClass(FormBuilder, UIRouter);
export {MnHelperReactService};