/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { BehaviorSubject, pipe, empty } from 'rxjs';
import {
  filter,
  map,
  switchMap,
  withLatestFrom,
  takeUntil,
} from 'rxjs/operators';
import { UISref } from '@uirouter/react';

import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnWizardService } from './mn.wizard.service.js';
import { MnAuthService } from './mn.auth.service.js';
import { MnFormService } from './mn.form.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnSecurityService } from './mn.security.service.js';
import mnPools from './components/mn_pools';
import { FieldGroup, FieldControl } from 'react-reactive-form';
import { UIRouter } from './mn.react.router';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { MnHostnameConfigComponent } from './mn.hostname.config.component.jsx';
import { MnServicesConfigComponent } from './mn.services.config.component.jsx';
import { MnNodeStorageConfigComponent } from './mn.node.storage.config.component.jsx';

class MnWizardJoinClusterComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      joinClusterHttpError: null,
      certificate: null,
      toggleConfigurationSection: false,
    };
  }

  componentWillMount() {
    this.mnHelperService = MnHelperService;

    this.focusFieldSubject = new BehaviorSubject('hostname');
    this.joinClusterForm = MnWizardService.wizardForm.joinCluster;
    this.joinClusterHttp = MnWizardService.stream.joinClusterHttp;

    this.certificate = MnPoolsService.stream.isEnterprise.pipe(
      switchMap((v) => (v ? MnSecurityService.stream.getCertificate : empty()))
    );

    this.form = MnFormService.create(this);

    this.form
      .setPackPipe(
        pipe(
          filter(this.isValid.bind(this)),
          withLatestFrom(MnPoolsService.stream.isEnterprise),
          map(([, isEnterprise]) => {
            let rv = {};
            var nodeStorage = this.joinClusterForm.get('clusterStorage');
            rv.hostname = nodeStorage.get('hostname').value;
            rv.dataPath = nodeStorage.get('storage.path').value;
            rv.indexPath = nodeStorage.get('storage.index_path').value;
            rv.eventingPath = nodeStorage.get('storage.eventing_path').value;
            rv.javaHome = nodeStorage.get('storage.java_home').value;
            if (isEnterprise) {
              rv.analyticsPath = nodeStorage.get('storage.cbas_path').value;
            }
            return rv;
          })
        )
      )
      .setPostRequest(MnWizardService.stream.postNodeInitHttp)
      .setPackPipe(
        map(() => {
          var data = this.joinClusterForm.get('clusterAdmin').value;
          var services = this.joinClusterForm.get('services.flag');
          data.newNodeHostname = this.joinClusterForm.get(
            'clusterStorage.hostname'
          ).value;
          var servicesValue = MnWizardService.getServicesValues(services);
          data.services = '';
          if (servicesValue.length) {
            data.services = servicesValue.join(',');
          }
          return data;
        })
      )
      .setPostRequest(this.joinClusterHttp)
      .setPackPipe(
        map(() => [this.joinClusterForm.get('clusterAdmin').value, false])
      )
      .setPostRequest(MnAuthService.stream.postUILogin)
      .clearErrors()
      .showGlobalSpinner()
      .success(() => {
        // TODO: implment this when maybeShowMemoryQuotaDialog is ready

        // let services = this.joinClusterForm.get("services.flag");
        // let servicesAsObject =
        //   MnHelperService.stringToObject(MnWizardService.getServicesValues(services).join(','));
        MnHelperReactService.mnGlobalSpinnerFlag.next(true);
        // $rootScope.$broadcast("maybeShowMemoryQuotaDialog", servicesAsObject);
        mnPools.clearCache();
        UIRouter.urlRouter.sync();
      });

    this.joinClusterHttpError = this.joinClusterHttp.error;
    MnHelperReactService.mnFocus(this);
    MnHelperReactService.async(this, 'joinClusterHttpError');
    MnHelperReactService.async(this, 'certificate');
  }

  isValid() {
    return !this.joinClusterForm.invalid;
  }

  render() {
    const { joinClusterHttpError, certificate, toggleConfigurationSection } =
      this.state;

    return (
      <div className="panel dialog-med dialog dialog-wizard">
        <div className="panel-header flex-left">
          <img
            src="./cb_logo_bug_white_2.svg"
            width="32"
            height="32"
            className="margin-right-half"
            alt="Couchbase Logo"
          />
          <h2>Couchbase &gt; Join Cluster</h2>
        </div>

        <FieldGroup
          control={this.joinClusterForm}
          strict={false}
          render={({ submitted }) => (
            <form
              className="forms"
              onSubmit={(e) => {
                e.preventDefault();
                this.form.submit.next();
                this.joinClusterForm.handleSubmit();
              }}
              noValidate
            >
              <div className="panel-content">
                <div
                  className="error error-form"
                  hidden={!joinClusterHttpError}
                >
                  {joinClusterHttpError &&
                    joinClusterHttpError.map((error, i) => (
                      <div key={i}>{error}</div>
                    ))}
                </div>

                <div className="error error-form">
                  <FieldControl
                    name="clusterAdmin.hostname"
                    render={({ touched, errors }) => (
                      <div
                        hidden={!(touched || submitted) || !errors?.required}
                      >
                        Cluster name is required
                      </div>
                    )}
                  />

                  <FieldControl
                    name="clusterAdmin.user"
                    render={({ touched, errors }) => (
                      <div
                        hidden={!(touched || submitted) || !errors?.required}
                      >
                        Username is required
                      </div>
                    )}
                  />

                  <FieldControl
                    name="clusterAdmin.password"
                    render={({ touched, errors }) => (
                      <div
                        hidden={!(touched || submitted) || !errors?.required}
                      >
                        Password is required
                      </div>
                    )}
                  />

                  <div hidden={certificate?.cert.type !== 'generated'}>
                    This node is using self-signed certificates. No peer
                    verification between nodes will be done.
                  </div>
                </div>

                <div>
                  <div className="formrow">
                    <label htmlFor="for-hostname-field">
                      Cluster Host Name/IP Address
                    </label>
                    <FieldControl
                      name="clusterAdmin.hostname"
                      render={({ handler }) => (
                        <input
                          ref={(input) => {
                            this.input = input;
                          }}
                          type="text"
                          id="for-hostname-field"
                          maxLength="256"
                          autoCorrect="off"
                          spellCheck="false"
                          autoCapitalize="off"
                          {...handler()}
                        />
                      )}
                    />
                  </div>

                  <div className="formrow">
                    <label htmlFor="secure-user">Cluster Admin Username</label>
                    <FieldControl
                      name="clusterAdmin.user"
                      render={({ handler }) => (
                        <input
                          type="text"
                          id="secure-user"
                          autoCorrect="off"
                          spellCheck="false"
                          autoCapitalize="off"
                          {...handler()}
                        />
                      )}
                    />
                  </div>

                  <div className="formrow">
                    <div className="column">
                      <label htmlFor="secure-password">
                        Cluster Admin Password
                      </label>
                      <FieldControl
                        name="clusterAdmin.password"
                        render={({ handler }) => (
                          <input
                            type="password"
                            id="secure-password"
                            autoCorrect="off"
                            spellCheck="false"
                            placeholder="Existing cluster password"
                            {...handler()}
                          />
                        )}
                      />
                    </div>
                  </div>
                </div>

                <div
                  className={`formrow disclosure ${toggleConfigurationSection ? 'disclosed' : ''}`}
                  onClick={() =>
                    this.setState({
                      toggleConfigurationSection:
                        !this.state.toggleConfigurationSection,
                    })
                  }
                >
                  Configure Services &amp; Settings For This Node
                </div>

                {toggleConfigurationSection && (
                  <>
                    <MnHostnameConfigComponent
                      group={this.joinClusterForm.get('clusterStorage')}
                    />
                    <MnServicesConfigComponent
                      group={this.joinClusterForm.get('services')}
                    />
                    <MnNodeStorageConfigComponent
                      group={this.joinClusterForm.get('clusterStorage')}
                    />
                  </>
                )}
              </div>

              <div className="panel-footer">
                <UISref to="app.wizard.welcome" options={{ location: false }}>
                  <a>&lt; Back</a>
                </UISref>
                <button disabled={this.joinClusterForm.invalid} type="submit">
                  Join Cluster
                </button>
              </div>
            </form>
          )}
        />
      </div>
    );
  }
}

export { MnWizardJoinClusterComponent };
