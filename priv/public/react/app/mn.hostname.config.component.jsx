/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { takeUntil, pluck, distinctUntilChanged } from 'rxjs/operators';
import { BehaviorSubject } from 'rxjs';
import { FieldGroup, FieldControl } from 'react-reactive-form';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';

import { MnPoolsService } from './mn.pools.service.js';
import { MnWizardService } from './mn.wizard.service.js';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnHostnameConfigComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      postNodeInitHttpError: null,
      postClusterInitHttpError: null,
      isEnterprise: null,
    };
  }

  getAddressFamilyUI() {
    return this.props.group.get('hostConfig.addressFamilyUI');
  }

  componentWillUnmount() {
    super.componentWillUnmount();
    this.props.group.valueChanges.unsubscribe();
  }

  componentDidMount() {
    this.focusFieldSubject = new BehaviorSubject(true);
    this.postNodeInitHttp = MnWizardService.stream.postNodeInitHttp;
    this.postClusterInitHttp = MnWizardService.stream.postClusterInitHttp;
    this.setupNetConfigHttp = MnWizardService.stream.setupNetConfigHttp;
    this.enableExternalListenerHttp =
      MnWizardService.stream.enableExternalListenerHttp;
    this.isEnterprise = MnPoolsService.stream.isEnterprise;

    this.postNodeInitHttpError = this.postNodeInitHttp.error;
    this.postClusterInitHttpError = this.postClusterInitHttp.error;

    MnHelperReactService.async(this, 'postNodeInitHttpError');
    MnHelperReactService.async(this, 'postClusterInitHttpError');
    MnHelperReactService.async(this, 'isEnterprise');
    MnHelperReactService.mnFocus(this);

    if (!this.props.isHostCfgEnabled) {
      return;
    }

    MnHelperReactService.valueChanges(this.props.group.valueChanges)
      .pipe(
        pluck('hostConfig', 'addressFamilyUI'),
        distinctUntilChanged(),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe((option) => {
        let hostname = this.props.group.get('hostname').value;

        if (
          (option == 'inet6' || option == 'inet6Only') &&
          hostname == '127.0.0.1'
        ) {
          this.props.group.get('hostname').setValue('::1');
        }
        if ((option == 'inet' || option == 'inetOnly') && hostname == '::1') {
          this.props.group.get('hostname').setValue('127.0.0.1');
        }
      });
  }

  render() {
    const { group, isHostCfgEnabled } = this.props;
    const { postNodeInitHttpError, postClusterInitHttpError, isEnterprise } =
      this.state;

    const nodeEncryptionTip = (
      <Tooltip>
        Network traffic between the individual nodes of a Couchbase Server
        cluster can be encrypted, in order to optimize cluster internal
        security.
      </Tooltip>
    );

    const ipFamilyTip = (
      <Tooltip>
        Selecting IPv4 or IPv6 will instruct services in the cluster to listen
        on those addresses, though as a convenience some services will also
        listen on the other address family. Selecting 'IPv4/IPv6-only' will
        instruct services to ONLY listen on the selected addresses.
      </Tooltip>
    );

    return (
      <div>
        <FieldGroup
          control={group}
          strict={false}
          render={() => (
            <div>
              <div className="formrow">
                <div className="row">
                  <label htmlFor="setup_hostname">Host Name / IP Address</label>
                  <small className="text-smaller">
                    Fully-qualified domain name
                  </small>
                </div>
                <FieldControl
                  name="hostname"
                  render={({ handler }) => (
                    <input
                      type="text"
                      autoCorrect="off"
                      spellCheck="false"
                      autoCapitalize="off"
                      id="setup_hostname"
                      ref={(input) => (this.input = input)}
                      {...handler()}
                    />
                  )}
                />
                <div
                  className="error error-form"
                  hidden={!postNodeInitHttpError?.errors?.hostname}
                >
                  {postNodeInitHttpError?.errors?.hostname}
                </div>
                <div
                  className="error error-form"
                  hidden={!postClusterInitHttpError?.errors?.hostname}
                >
                  {postClusterInitHttpError?.errors?.hostname}
                </div>
              </div>

              {isHostCfgEnabled && isEnterprise && (
                <FieldGroup
                  name="hostConfig"
                  render={() => (
                    <div>
                      <div className="formrow">
                        <FieldControl
                          name="nodeEncryption"
                          render={({ handler }) => (
                            <>
                              <input
                                type="checkbox"
                                id="for-node-encryption"
                                {...handler()}
                              />
                              <label
                                htmlFor="for-node-encryption"
                                className="margin-right-quarter"
                              >
                                enable node-to-node encryption
                              </label>
                            </>
                          )}
                        />
                        <OverlayTrigger
                          placement="right"
                          overlay={nodeEncryptionTip}
                        >
                          <span className="fa-stack icon-info">
                            <span className="icon fa-circle-thin fa-stack-2x"></span>
                            <span className="icon fa-info fa-stack-1x"></span>
                          </span>
                        </OverlayTrigger>
                        <div
                          className="error error-form"
                          hidden={
                            !postClusterInitHttpError?.errors?.nodeEncryption
                          }
                        >
                          {postClusterInitHttpError?.errors?.nodeEncryption}
                        </div>
                      </div>

                      <label className="inline margin-right-quarter">
                        IP Family Preference
                      </label>
                      <OverlayTrigger placement="right" overlay={ipFamilyTip}>
                        <span className="fa-stack icon-info">
                          <span className="icon fa-circle-thin fa-stack-2x"></span>
                          <span className="icon fa-info fa-stack-1x"></span>
                        </span>
                      </OverlayTrigger>

                      <div className="formrow">
                        <div className="form-inline">
                          <FieldControl
                            name="addressFamilyUI"
                            strict={false}
                            render={({ handler }) => {
                              const { value, ...handlerSwitch } =
                                handler('switch');
                              return (
                                <>
                                  <input
                                    checked={value == 'inet'}
                                    type="radio"
                                    name="addressFamilyUI"
                                    value="inet"
                                    id="for-use-ipv4"
                                    {...handlerSwitch}
                                  />
                                  <label htmlFor="for-use-ipv4">IPv4</label>

                                  <input
                                    checked={value == 'inet6'}
                                    type="radio"
                                    name="addressFamilyUI"
                                    value="inet6"
                                    id="for-use-ipv6"
                                    {...handlerSwitch}
                                  />
                                  <label htmlFor="for-use-ipv6">IPv6</label>

                                  <input
                                    checked={value == 'inetOnly'}
                                    type="radio"
                                    name="addressFamilyUI"
                                    value="inetOnly"
                                    id="for-use-ipv4-only"
                                    {...handlerSwitch}
                                  />
                                  <label htmlFor="for-use-ipv4-only">
                                    IPv4-only
                                  </label>

                                  <input
                                    checked={value == 'inet6Only'}
                                    type="radio"
                                    name="addressFamilyUI"
                                    value="inet6Only"
                                    id="for-use-ipv6-only"
                                    {...handlerSwitch}
                                  />
                                  <label htmlFor="for-use-ipv6-only">
                                    IPv6-only
                                  </label>
                                </>
                              );
                            }}
                          />
                        </div>
                        {this.getAddressFamilyUI()?.hasError('ipvOnly') && (
                          <div className="error error-form">
                            Can't set IPv
                            {this.getAddressFamilyUI().errors?.ipvOnly.value}
                            -only from an IPv
                            {this.getAddressFamilyUI().errors?.ipvOnly.kind}{' '}
                            address; please access this server via an IPv
                            {this.getAddressFamilyUI().errors?.ipvOnly.value}{' '}
                            address
                          </div>
                        )}
                        {this.getAddressFamilyUI()?.warnings?.ipvOnly && (
                          <div className="error error-form">
                            You have selected IPv
                            {this.getAddressFamilyUI().warnings?.ipvOnly.value}
                            -only. If the domain name with which you have
                            accessed this server is only available under IPv
                            {this.getAddressFamilyUI().warnings?.ipvOnly.value}{' '}
                            you will not be able to complete initialization
                          </div>
                        )}
                        <div
                          className="error error-form"
                          hidden={!postClusterInitHttpError?.errors?.afamily}
                        >
                          {postClusterInitHttpError?.errors?.afamily}
                        </div>
                        <div
                          className="error error-form"
                          hidden={
                            !postClusterInitHttpError?.errors?.afamilyOnly
                          }
                        >
                          {postClusterInitHttpError?.errors?.afamilyOnly}
                        </div>
                      </div>
                    </div>
                  )}
                />
              )}
            </div>
          )}
        />
      </div>
    );
  }
}

export { MnHostnameConfigComponent };
