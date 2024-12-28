/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import React from 'react';
import { FormControl } from 'react-reactive-form';
import { takeUntil } from 'rxjs/operators';
import { FieldGroup, FieldControl, FieldArray } from 'react-reactive-form';

import { MnPoolsService } from './mn.pools.service.js';
import { MnWizardService } from './mn.wizard.service.js';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnPathFieldComponent } from './mn.path.field.component.jsx';

export class MnNodeStorageConfigComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      isEnterprise: false,
      postNodeInitHttpError: null,
      postClusterInitHttpError: null
    };
  }

  componentWillMount() {
    this.isEnterprise = MnPoolsService.stream.isEnterprise;
    this.postNodeInitHttp = MnWizardService.stream.postNodeInitHttp;
    this.postClusterInitHttp = MnWizardService.stream.postClusterInitHttp;

    this.isEnterprise
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(isEnterprise => this.setState({isEnterprise}));

    this.postNodeInitHttp.error
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(error => this.setState({postNodeInitHttpError: error}));

    this.postClusterInitHttp.error
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(error => this.setState({postClusterInitHttpError: error}));
  }

  addCbasPathField = () => {
    const last = this.props.group.get('storage.cbas_path').length - 1;
    this.props.group
      .get('storage.cbas_path')
      .push(new FormControl(this.props.group.get('storage.cbas_path').value[last]));
  }

  removeCbasPathField = () => {
    const last = this.props.group.get('storage.cbas_path').length - 1;
    this.props.group.get('storage.cbas_path').removeAt(last);
  }

  render() {
    const { group } = this.props;
    const { isEnterprise, postNodeInitHttpError, postClusterInitHttpError } = this.state;

    return (
      <FieldGroup control={group} strict={false} render={() => (
        <div>
          <div 
            className="error error-form"
            hidden={!postNodeInitHttpError?.errors?._}>
            {postNodeInitHttpError?.errors?._}
          </div>

          <div>
            <div>
              <div className="formrow">
                <div className="row">
                  <label htmlFor="setup_db_path_input">Data Disk Path</label>
                  <small className="text-smaller">Path cannot be changed after setup</small>
                </div>
                <MnPathFieldComponent
                  control={group.get('storage.path')}
                  controlName="setup_db_path_input" />
              </div>
              <div
                className="error"
                hidden={!postClusterInitHttpError?.errors?.path}>
                {postClusterInitHttpError?.errors?.path}
              </div>

              <div className="formrow">
                <div className="row">
                  <label htmlFor="setup_index_path_input">Indexes Disk Path</label>
                  <small className="text-smaller">Used by GSI, FTS, and Views</small>
                </div>
                <MnPathFieldComponent
                  control={group.get('storage.index_path')}
                  controlName="setup_index_path_input" />
              </div>
              <div
                className="error"
                hidden={!postClusterInitHttpError?.errors?.index_path}>
                {postClusterInitHttpError?.errors?.index_path}
              </div>

              {isEnterprise && (
                <div className="formrow">
                  <div className="row">
                    <label htmlFor="setup_eventing_path_input">Eventing Disk Path</label>
                    <small className="text-smaller">Path cannot be changed after setup</small>
                  </div>
                  <MnPathFieldComponent
                    control={group.get('storage.eventing_path')}
                    controlName="setup_eventing_path_input" />
                </div>
              )}
              <div
                className="error"
                hidden={!postClusterInitHttpError?.errors?.eventing_path}>
                {postClusterInitHttpError?.errors?.eventing_path}
              </div>

              {isEnterprise && (
                <div className="formrow">
                  <div className="row">
                    <label htmlFor="setup_cbas_path_input0">Analytics Disk Paths</label>
                    <small className="text-smaller">Paths cannot be changed after setup</small>
                  </div>
                  <div>
                    <FieldArray
                      control={group.get('storage.cbas_path')}
                      strict={false}
                      render={(data) => {
                        return data.controls.map((control, i) => {
                          return (<div className="formrow" key={i}>
                            <MnPathFieldComponent
                              control={control}
                              controlName={`setup_cbas_path_input${i}`} />
                          </div>
                        )})}
                      }/>
                  </div>
                  {/* <div>
                    {group.get('storage.cbas_path').controls.map((control, i) => {
                      console.log(control);
                      return (<div className="formrow" key={i}>
                        <MnPathFieldComponent
                          control={control}
                          controlName={`setup_cbas_path_input${i}`} />
                      </div>
                    )})}
                  </div> */}
                </div>
              )}

              {isEnterprise && (
                <div className="row formrow flex-right margin-top-neg-2">
                  <button
                    className="outline btn-small"
                    title="Add field"
                    onClick={this.addCbasPathField}
                    type="button">+</button>
                  <button
                    className="outline btn-small"
                    title="Remove field"
                    disabled={group.get('storage.cbas_path').length === 1}
                    onClick={this.removeCbasPathField}
                    type="button">-</button>
                </div>
              )}
              <div
                className="error"
                hidden={!postClusterInitHttpError?.errors?.cbas_path}>
                {postClusterInitHttpError?.errors?.cbas_path}
              </div>
            </div>
          </div>
        </div>
      )} />
    );
  }
} 