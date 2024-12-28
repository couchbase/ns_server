/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { BehaviorSubject } from 'rxjs';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnWizardService } from './mn.wizard.service.js';
import { FieldControl } from 'react-reactive-form';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnPathFieldComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.focusFieldSubject = new BehaviorSubject(true);
    this.state = {
      lookUpPath: null
    };
  }

  componentWillMount() {
    this.lookUpPath = MnWizardService.createLookUpStream(MnHelperReactService.valueChanges(this.props.control.valueChanges));
    MnHelperReactService.async(this, 'lookUpPath');

    setTimeout(() => {
      //trigger storageGroup.valueChanges for lookUpIndexPath,lookUpDBPath
      this.props.control.setValue(this.props.control.value);
    }, 0);
  }

  componentWillUnmount() {
    super.componentWillUnmount();
    this.props.control.valueChanges.unsubscribe();
  }

  render() {
    const { control, controlName } = this.props;
    const { lookUpPath } = this.state;

    return (
      <>
        <FieldControl
          control={control}
          render={({ handler }) => {
            return (<input
              type="text"
              autoCorrect="off"
              spellCheck="false"
              autoCapitalize="off"
              id={controlName}
              {...handler()}
            />
          )}}
        />
        <p>
          Free: {lookUpPath}
        </p>
      </>
    );
  }
}

export { MnPathFieldComponent };
