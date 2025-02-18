import React from 'react';
import { MnLifeCycleHooksToStream } from 'mn.core';
import { UIRouter } from 'mn.react.router';
import { FieldGroup, FieldControl } from 'react-reactive-form';
import { combineLatest } from 'rxjs';
import { map, takeUntil } from 'rxjs/operators';
import MnPermissions from './components/mn_permissions.js';
import { MnFormService } from './mn.form.service.js';
import { MnSecurityService } from './mn.security.service.js';
import { MnAdminService } from './mn.admin.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnHttpGroupRequest } from './mn.http.request.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { MnSpinner } from './components/directives/mn_spinner.jsx';
import { MnSelect } from './components/directives/mn_select/mn_select.jsx';
import { all } from 'ramda';
import { Tooltip } from 'react-bootstrap';
import { OverlayTrigger } from './components/lib/overlay-trigger.jsx';
import { UISref } from '@uirouter/react';

export class MnSecurityOtherComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      postLogRedactionRequestError: null,
      postSettingsSecurityError: null,
      mnPermissions: null,
      isEnterprise: null,
      isEnterpriseAnd55: null,
      isClusterEncryptionEnabled: null,
      majorMinorVersion: null,
      formLoading: null,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    this.form = MnFormService.create(this);
    this.form
      .setFormGroup({
        logRedactionLevel: this.form.builder.group({
          logRedactionLevel: null,
        }),
        settingsSecurity: this.form.builder.group({
          uiSessionTimeout: null,
          clusterEncryptionLevel: null,
        }),
      })
      .setSource(MnSecurityService.stream.prepareOtherSettingsFormValues)
      .setPackPipe(map(this.packData.bind(this)))
      .setPostRequest(
        new MnHttpGroupRequest({
          logRedactionLevel: MnSecurityService.stream.postLogRedaction,
          settingsSecurity: MnSecurityService.stream.postSettingsSecurity,
        })
          .addSuccess()
          .addError()
      )
      .setReset(UIRouter.stateService.reload)
      .successMessage('Settings saved successfully!');

    this.formLoading = this.form.loadingPipe;
    MnHelperReactService.async(this, 'formLoading');

    this.majorMinorVersion = MnAdminService.stream.majorMinorVersion;
    MnHelperReactService.async(this, 'majorMinorVersion');

    this.isClusterEncryptionEnabled =
      MnAdminService.stream.isClusterEncryptionEnabled;
    MnHelperReactService.async(this, 'isClusterEncryptionEnabled');

    this.isEnterprise = MnPoolsService.stream.isEnterprise;
    MnHelperReactService.async(this, 'isEnterprise');

    this.compatVersion55 = MnAdminService.stream.compatVersion55;

    this.postLogRedactionRequest = MnSecurityService.stream.postLogRedaction;

    this.postLogRedactionRequestError = this.postLogRedactionRequest.error;
    MnHelperReactService.async(this, 'postLogRedactionRequestError');

    this.postSettingsSecurity = MnSecurityService.stream.postSettingsSecurity;

    this.postSettingsSecurityError = this.postSettingsSecurity.error;
    MnHelperReactService.async(this, 'postSettingsSecurityError');

    this.isEnterpriseAnd55 = combineLatest(
      this.isEnterprise,
      this.compatVersion55
    ).pipe(map(all(Boolean)));
    MnHelperReactService.async(this, 'isEnterpriseAnd55');

    MnPermissions.stream
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((permissions) => {
        let write = permissions.cluster.admin.security.write;
        this.maybeDisableField('settingsSecurity.uiSessionTimeout', write);
        this.maybeDisableField('logRedactionLevel.logRedactionLevel', write);
        this.setState({ mnPermissions: permissions });
      });

    combineLatest(MnPermissions.stream, this.isClusterEncryptionEnabled)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(([permissions, enabled]) => {
        let write = permissions.cluster.admin.security.write;
        this.maybeDisableField(
          'settingsSecurity.clusterEncryptionLevel',
          enabled && write
        );
      });
  }

  packData() {
    let formValue = this.form.group.value;
    let result = new Map();

    let timeout = Number(formValue.settingsSecurity.uiSessionTimeout);
    let redaction = formValue.logRedactionLevel.logRedactionLevel;
    let encryptionLevel = formValue.settingsSecurity.clusterEncryptionLevel;

    let securityValue = {};
    securityValue.uiSessionTimeout = timeout ? timeout * 60 : '';
    if (encryptionLevel) {
      securityValue.clusterEncryptionLevel = encryptionLevel;
    }

    result.set('settingsSecurity', securityValue);
    if (redaction !== null) {
      result.set('logRedactionLevel', formValue.logRedactionLevel);
    }

    return result;
  }

  maybeDisableField(field, value) {
    this.form.group.get(field)[value ? 'enable' : 'disable']();
  }

  renderClusterEncryptionTooltip() {
    const { isClusterEncryptionEnabled, majorMinorVersion } = this.state;

    return (
      <Tooltip>
        {!isClusterEncryptionEnabled && (
          <p>
            <span className="icon-info-warning">
              <span className="icon fa-warning"></span>
            </span>{' '}
            &nbsp;
            <strong>
              Cluster encryption is disabled. Please use{' '}
              <a
                href={`https://docs.couchbase.com/server/${majorMinorVersion}/cli/cbcli/couchbase-cli.html`}
                target="_blank"
                rel="noopener noreferrer"
              >
                Couchbase CLI
              </a>{' '}
              to enable it. Once enabled, you may change encryption levels here.
              Altering the cluster encryption is disabled while auto-failover is
              enabled.
            </strong>
          </p>
        )}
        <p>Cluster encryption levels are:</p>
        <p className="margin-bottom-half">
          <strong>control</strong>:&nbsp; cluster management traffic is
          encrypted
        </p>
        <p className="margin-bottom-half">
          <strong>all</strong>:&nbsp; all traffic between nodes is encrypted
        </p>
        <p className="margin-bottom-half">
          <strong>strict</strong>:&nbsp; all traffic between nodes is encrypted
          and no ports accepting unencrypted traffic are open
        </p>
        <p>
          Warning: setting the encryption level to strict may cause clients with
          unencrypted connections to have their service interrupted.
        </p>
      </Tooltip>
    );
  }

  render() {
    const {
      postLogRedactionRequestError,
      postSettingsSecurityError,
      mnPermissions,
      isEnterprise,
      isEnterpriseAnd55,
      formLoading,
    } = this.state;

    if (formLoading || !this.form) {
      return <MnSpinner mnSpinner={true} />;
    }

    return (
      <>
        <FieldGroup
          control={this.form.group}
          strict={false}
          render={() => (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                this.form.submit.next();
              }}
            >
              <div
                className="error error-form"
                hidden={!postLogRedactionRequestError?.errors}
              >
                {postLogRedactionRequestError?.errors &&
                  Object.entries(postLogRedactionRequestError.errors).map(
                    ([key, value]) => (
                      <div key={key}>
                        {key} - {value}
                      </div>
                    )
                  )}
              </div>
              <div
                className="error error-form"
                hidden={!postSettingsSecurityError?.errors}
              >
                {postSettingsSecurityError?.errors?.map((error, i) => (
                  <div key={i}>{error}</div>
                ))}
              </div>

              {isEnterpriseAnd55 && (
                <div className="formrow">
                  <label>Log Redaction</label>
                  <div className="desc">
                    Default setting for redacting logs during{' '}
                    <UISref to="app.admin.logs.collectInfo.form">
                      <a>collect info</a>
                    </UISref>{' '}
                  </div>
                  <FieldControl
                    name="logRedactionLevel.logRedactionLevel"
                    strict={false}
                    render={({ handler }) => {
                      const field = handler('switch');
                      return (
                        <>
                          <input
                            {...field}
                            type="radio"
                            value="none"
                            checked={field.value === 'none'}
                            id="redaction_none"
                          />
                          <label htmlFor="redaction_none" className="checkbox">
                            {' '}
                            None
                          </label>
                          <br />
                          <input
                            {...field}
                            type="radio"
                            value="partial"
                            checked={field.value === 'partial'}
                            id="redaction_partial"
                          />
                          <label
                            htmlFor="redaction_partial"
                            className="checkbox margin-right-quarter"
                          >
                            {' '}
                            Partial Redaction
                          </label>{' '}
                          <OverlayTrigger
                            placement="right"
                            allowContentHover
                            overlay={
                              <Tooltip>
                                User data such as key/value pairs and usernames
                                will be redacted. Metadata and system data will
                                not be redacted.
                              </Tooltip>
                            }
                          >
                            <span className="fa-stack icon-info">
                              <span className="icon fa-circle-thin fa-stack-2x"></span>
                              <span className="icon fa-info fa-stack-1x"></span>
                            </span>
                          </OverlayTrigger>
                        </>
                      );
                    }}
                  />
                </div>
              )}

              <div className="formrow block margin-bottom-2">
                <label>Session Timeout</label>
                <div className="desc">
                  Minutes until an inactive browser session is closed. <br />
                  Leave empty (or zero) for no timeout.
                </div>
                <div className="form-inline">
                  <FieldControl
                    name="settingsSecurity.uiSessionTimeout"
                    strict={false}
                    render={({ handler }) => (
                      <>
                        <input
                          id="session-field"
                          type="number"
                          className="input-short-1"
                          autocorrect="off"
                          spellcheck="false"
                          autocapitalize="off"
                          {...handler()}
                        />
                        <small> min</small>
                      </>
                    )}
                  />
                </div>
              </div>

              {isEnterprise && (
                <div className="block margin-bottom-4">
                  <label>
                    Cluster Encryption{' '}
                    <OverlayTrigger
                      allowContentHover
                      placement="right"
                      overlay={this.renderClusterEncryptionTooltip()}
                    >
                      <span className="fa-stack icon-info margin-left-quarter">
                        <span className="icon fa-circle-thin fa-stack-2x"></span>
                        <span className="icon fa-info fa-stack-1x"></span>
                      </span>
                    </OverlayTrigger>
                  </label>
                  <FieldControl
                    name="settingsSecurity.clusterEncryptionLevel"
                    strict={false}
                    render={({ handler }) => {
                      const field = handler();
                      return (
                        <MnSelect
                          mnDisabled={
                            !mnPermissions?.cluster.admin.security.write ||
                            field.disabled
                          }
                          values={['control', 'all', 'strict']}
                          labels={['control', 'all', 'strict']}
                          className="inline fix-width-2"
                          onSelect={({ selectedOption }) => {
                            field.onChange(selectedOption);
                          }}
                          {...field}
                        />
                      );
                    }}
                  />
                </div>
              )}

              <footer
                className="footer-save"
                hidden={!mnPermissions?.cluster.admin.security.write}
              >
                <button type="submit" className="margin-right-2">
                  Save
                </button>
                <a
                  className="text-medium"
                  onClick={(e) => {
                    e.preventDefault();
                    this.form.reset.next();
                  }}
                >
                  Cancel/Reset
                </a>
              </footer>
            </form>
          )}
        />
      </>
    );
  }
}
