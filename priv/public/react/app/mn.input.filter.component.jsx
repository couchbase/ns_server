import React from 'react';
import {startWith} from 'rxjs/operators';
import { FieldGroup, FieldControl } from "react-reactive-form";

import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnInputFilter extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      currentValue: props.group.get('value').value,
      valueChanges: null,
    };
  }

  componentDidMount() {
    MnHelperReactService.mnFocus({
      focusFieldSubject: this.props.mnFocus,
      mnName: this.props.mnName,
      input: this.input,
      mnOnDestroy: this.mnOnDestroy
    });

    let value = this.props.group.get('value');
    this.valueChanges = MnHelperReactService.valueChanges(value.valueChanges);
    this.currentValue = this.valueChanges.pipe(startWith(value.value));
    MnHelperReactService.async(this, 'currentValue');
    MnHelperReactService.async(this, 'valueChanges');
  }

  componentWillUnmount() {
    super.componentWillUnmount();
    this.props.group.get('value').valueChanges.unsubscribe();
  }

  handleBlur = () => {
    this.props.mnFocusStatus && this.props.mnFocusStatus.next(false);
  };

  handleFocus = () => {
    this.props.mnFocusStatus && this.props.mnFocusStatus.next(true);
  };

  render() {
    const { group, mnClearDisabled, mnPlaceholder, mnName, className } = this.props;
    const { currentValue, valueChanges } = this.state;

    return (
      <FieldGroup
        control={group}
        render={() => (
          <div className={`filter-input-group ${className}`}>
            <FieldControl
              name="value"
              render={({ handler }) => (
                <>
                  <input
                    {...handler()}
                    ref={(input) => { this.input = input; }} 
                    type="text"
                    name={mnName}
                    maxLength="256"
                    placeholder={mnPlaceholder}
                    onBlur={this.handleBlur}
                    onFocus={this.handleFocus}
                    onClick={(e) => e.stopPropagation()}
                    className={`filter-input ${!currentValue ? 'selected' : ''}`}
                  />
                  <span
                    className="icon fa-search-minus"
                    hidden={valueChanges || this.props.group.get('value').disabled}
                  ></span>
                  {!mnClearDisabled && (
                    <span
                      className="icon fa-times-circle"
                      hidden={!valueChanges}
                      onClick={(e) => {
                        e.stopPropagation();
                        group.patchValue({value: ''});
                      }}
                    ></span>
                  )}
                </>
              )}
            />
        </div>
      )}
    />
    );
  }
}

export { MnInputFilter };
