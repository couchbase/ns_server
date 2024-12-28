/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {combineLatest, of} from 'rxjs';
import {takeUntil, map, first, startWith, filter} from 'rxjs/operators';
import {not, any, all} from 'ramda';
import {FieldControl} from 'react-reactive-form';
import {OverlayTrigger, Tooltip} from 'react-bootstrap';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnHelperReactService} from './mn.helper.react.service.js';

class MnStorageModeComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    
    this.state = {
      showForestDB: false,
      isEnterprise: false,
      indexesHttpError: null
    };
  }

  componentWillMount() {
    this.indexesHttp = MnWizardService.stream.indexesHttp;
    this.isEnterprise = MnPoolsService.stream.isEnterprise;
    
    var isNotEnterprise = this.isEnterprise.pipe(map(not));
    var isFirstValueForestDB = MnHelperReactService.valueChanges(this.props.control.valueChanges).pipe(
      startWith(this.props.control.value),
      filter(v => !!v),
      first(),
      map(v => v == "forestdb")
    );

    var indexFlag = this.props.indexFlag ?
      MnHelperReactService.valueChanges(this.props.indexFlag.valueChanges).pipe(startWith(this.props.indexFlag.value)) : of(true);

    this.showForestDB =
      combineLatest(isNotEnterprise, isFirstValueForestDB)
      .pipe(map(any(Boolean)));

    // Handle control enable/disable
    combineLatest(this.isEnterprise, indexFlag, this.props.permissionsIndexWrite || of(true))
      .pipe(
        map(all(Boolean)),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe(this.doDisableControl.bind(this));
    
    this.indexesHttpError = this.indexesHttp.error;
    MnHelperReactService.async(this, 'showForestDB');
    MnHelperReactService.async(this, 'indexesHttpError');
    MnHelperReactService.async(this, 'isEnterprise');
  }

  componentWillUnmount() {
    super.componentWillUnmount();
    if (this.props.indexFlag) {
      this.props.indexFlag.valueChanges.unsubscribe();
    }
  }

  doDisableControl(value) {
    this.props.control[value ? "enable" : "disable"]();
  }

  render() {
    const {showForestDB, isEnterprise, indexesHttpError} = this.state;
    const {control} = this.props;

    return (
      <div className="checkbox-list storage-mode formrow">
        {showForestDB && (
          <div>
            <FieldControl
              control={control}
              name="storageMode"
              render={({handler}) => (
                <input
                  type="radio"
                  value="forestdb"
                  id="storage_mode_forestdb"
                  {...handler()}
                />
              )}
            />
            <label htmlFor="storage_mode_forestdb" className="checkbox">
              {isEnterprise ? 'Legacy' : 'Standard'} Global Secondary
            </label>
          </div>
        )}
        
        {isEnterprise && (
          <div>
            <FieldControl
              control={control}
              name="storageMode"
              render={({handler}) => {
                const {value, ...handlerInput} = handler('switch');
                return <input
                  type="radio"
                  checked={value == "plasma"}
                  value="plasma"
                  id="storage_plasma_indexes"
                  {...handlerInput}
                />
              }}
            />
            <label htmlFor="storage_plasma_indexes" className="checkbox">
              Standard Global Secondary
            </label>
          </div>
        )}
        
        <div>
          <FieldControl
            control={control}
            name="storageMode"
            render={({handler}) => {
              const {value, ...handlerInput} = handler('switch');
              return (
                <input
                  type="radio"
                  checked={value == "memory_optimized"}
                  value="memory_optimized"
                  id="storage_memory_optimized"
                  {...handlerInput}
                />
              )
            }}
          />
          <label htmlFor="storage_memory_optimized" className="checkbox margin-right-quarter">
            Memory-Optimized
          </label>
          <OverlayTrigger
            placement="right"
            overlay={
              <Tooltip>
                Memory-optimized indexing is highly performant but requires careful attention to your index RAM quota. It is an Enterprise-only feature.
              </Tooltip>
            }
          >
            <span
              className="fa-stack icon-info"
              data-placement="right">
              <span className="icon fa-circle-thin fa-stack-2x"></span>
              <span className="icon fa-info fa-stack-1x"></span>
            </span>
          </OverlayTrigger>
        </div>

        <div
          className="error error-field"
          hidden={!indexesHttpError?.errors?.storageMode}>
          {indexesHttpError?.errors?.storageMode}
        </div>
      </div>
    );
  }
}

export {MnStorageModeComponent};