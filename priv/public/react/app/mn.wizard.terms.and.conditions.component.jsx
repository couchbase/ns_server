/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { BehaviorSubject, pipe } from 'rxjs';
import { filter, map, switchMap, combineLatest } from 'rxjs/operators';

import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnWizardService } from './mn.wizard.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnFormService } from './mn.form.service.js';
import { MnAuthService } from './mn.auth.service.js';
import { MnAdminService } from './mn.admin.service.js';
import mnPools from './components/mn_pools.js';
import { clone } from 'ramda';
import { UIRouter } from 'mn.react.router';
import { FieldGroup, FieldControl } from 'react-reactive-form';
import { UISref } from '@uirouter/react';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnWizardTermsAndConditionsComponent extends MnLifeCycleHooksToStream {
  constructor() {
    super();
    this.state = {
      isEnterprise: null,
      majorMinorVersion: null,
      servicesHttpError: null,
      license: null,
      termsHref: null,
      defaultFormSubmitted: false,
    };
  }

  componentWillMount() {
    this.focusFieldSubject = new BehaviorSubject(true);
    this.form = MnFormService.create(this);
    this.defaultForm = MnFormService.create(this);

    MnWizardService.wizardForm.termsAndConditions.get('agree').setValue(false);

    this.uiRouter = UIRouter;
    this.isEnterprise = MnPoolsService.stream.isEnterprise;
    this.wizardForm = MnWizardService.wizardForm;
    this.initialValues = MnWizardService.initialValues;
    this.majorMinorVersion = MnAdminService.stream.majorMinorVersion;

    this.groupHttp = MnWizardService.stream.groupHttp;
    this.secondGroupHttp = MnWizardService.stream.secondGroupHttp;
    this.servicesHttp = MnWizardService.stream.servicesHttp;
    this.mnWizardService = MnWizardService;

    this.license = MnPoolsService.stream.isEnterprise.pipe(
      switchMap(this.getLicense.bind(this))
    );

    this.termsHref = MnPoolsService.stream.isEnterprise.pipe(
      map(this.getTermsAndCond.bind(this))
    );

    this.servicesHttpError = MnWizardService.stream.servicesHttp.error;

    MnHelperReactService.async(this, 'servicesHttpError');
    MnHelperReactService.async(this, 'majorMinorVersion');
    MnHelperReactService.async(this, 'isEnterprise');
    MnHelperReactService.async(this, 'license');
    MnHelperReactService.async(this, 'termsHref');
    MnHelperReactService.mnFocus(this);

    this.form
      .setFormGroup(MnWizardService.wizardForm.termsAndConditions)
      .setPackPipe(filter(this.isValid.bind(this)))
      .hasNoPostRequest()
      .success(this.onSuccess.bind(this));

    this.defaultForm
      .setPackPipe(
        pipe(
          filter(this.isValid.bind(this)),
          combineLatest(
            MnPoolsService.stream.mnServices,
            MnPoolsService.stream.isEnterprise
          ),
          map(this.getClusterInitConfig.bind(this))
        )
      )
      .setPostRequest(MnWizardService.stream.postClusterInitHttp)
      .setPackPipe(map(MnWizardService.getUserCreds.bind(MnWizardService)))
      .setPostRequest(MnAuthService.stream.postUILogin)
      .clearErrors()
      .showGlobalSpinner()
      .success(() => {
        mnPools.clearCache();
        UIRouter.urlRouter.sync();
      });

    this.defaultFormSubmitted = this.defaultForm.submit;
    MnHelperReactService.async(this, 'defaultFormSubmitted');
  }

  onSuccess() {
    this.uiRouter.stateService.go('app.wizard.clusterConfiguration', null, {
      location: false,
    });
  }

  isValid() {
    return !this.form.group.invalid && this.form.group.get('agree').value;
  }

  getLicense(isEnterprise) {
    return isEnterprise
      ? this.mnWizardService.getEELicense()
      : this.mnWizardService.getCELicense();
  }

  getTermsAndCond(isEnterprise) {
    return isEnterprise
      ? 'https://www.couchbase.com/LA03012021'
      : 'https://www.couchbase.com/community-license-agreement04272021';
  }

  getClusterInitConfig([, services, isEnterprise]) {
    let userData = clone(this.wizardForm.newCluster.value.user);
    delete userData.passwordVerify;
    userData.port = 'SAME';
    return Object.assign(
      {
        hostname: this.initialValues.hostname,
        services: services.join(','),
        sendStats: isEnterprise
          ? this.wizardForm.termsAndConditions.get('enableStats').value
          : true,
        clusterName: this.wizardForm.newCluster.get('clusterName').value,
        setDefaultMemQuotas: true,
        indexerStorageMode: isEnterprise ? 'plasma' : 'forestdb',
      },
      userData
    );
  }

  render() {
    const {
      isEnterprise,
      majorMinorVersion,
      servicesHttpError,
      license,
      termsHref,
      defaultFormSubmitted,
    } = this.state;

    const tipContent = (
      <Tooltip>
        <ul>
          <li>Enable all services on this node (safest if you're exploring)</li>
          <li>Allocate memory automatically for Couchbase services</li>
          <li>Use default disk paths</li>
        </ul>
      </Tooltip>
    );

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
          <h2>Couchbase &gt; New Cluster</h2>
        </div>

        <FieldGroup
          strict={false}
          control={this.form.group}
          render={({ submitted }) => (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                this.form.submit.next();
                this.form.group.handleSubmit();
              }}
              className="forms"
            >
              <div className="panel-content">
                <h4 className="inline">Terms and Conditions&nbsp;</h4>
                {isEnterprise ? (
                  <>
                    <small>Enterprise Edition</small>
                    <div className="formrow text-small">
                      <i>
                        Couchbase Server must be licensed for use in production
                        environments.
                      </i>
                    </div>
                  </>
                ) : (
                  <small>Community Edition</small>
                )}

                <div className="formrow">
                  <textarea
                    className="text-smaller"
                    rows="10"
                    readOnly={true}
                    value={license}
                  />
                </div>

                <FieldControl
                  name="agree"
                  strict={false}
                  render={({ touched, value }) => (
                    <div
                      className="error error-form"
                      hidden={
                        !(touched || submitted || defaultFormSubmitted) ||
                        !!value
                      }
                    >
                      Terms and conditions need to be accepted in order to
                      continue
                    </div>
                  )}
                />

                <div className="error error-form" hidden={!servicesHttpError}>
                  {servicesHttpError &&
                    servicesHttpError.map((error, i) => (
                      <div key={i}>{error}</div>
                    ))}
                </div>

                <div className="row">
                  <div className="formrow">
                    <FieldControl
                      strict={false}
                      name="agree"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-accept-terms"
                            {...handler('checkbox')}
                          />
                          <label
                            className="text-small"
                            htmlFor="for-accept-terms"
                          >
                            I accept the{' '}
                            <a
                              href={termsHref}
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              terms & conditions
                            </a>
                          </label>
                        </>
                      )}
                    />
                  </div>
                </div>

                <h4>Software Updates & Usage Information</h4>
                <div className="formrow">
                  <textarea
                    className="text-smaller"
                    rows="5"
                    readOnly
                    value={
                      isEnterprise
                        ? 'When the following checkbox is enabled, this product automatically collects configuration, usage, and performance data, including cluster information (such as settings and configuration, software version, cluster ID, load levels, and resource quotas), and browser information (such as IP address, inferred geolocation at the city level, and browser type) (collectively with the foregoing, the “Performance Data”). The Performance Data is used by Couchbase to develop and improve our products as well as inform our sales and marketing programs. We do not access or collect any data stored in the Couchbase products. We use this Performance Data to understand aggregate usage patterns and make our products more useful to you. The Performance Data is collected by Couchbase when you access the Admin Console in the configuration wizard if this checkbox is selected. You may turn this feature off at any time from the Admin Console settings page. You can find out more about what data is collected and how it is used if you choose to keep this checkbox enabled in the privacy FAQ (link below), which supplements Couchbase&apos;s privacy policy (link below).'
                        : 'This product automatically collects configuration, usage, and performance data, including cluster information (such as settings and configuration, software version, cluster ID, load levels, and resource quotas), and browser information (such as IP address, inferred geolocation at the city level, and browser type) (collectively with the foregoing, the “Performance Data”). The Performance Data is used by Couchbase to develop and improve our products as well as inform our sales and marketing programs. We do not access or collect any data stored in the Couchbase products. We use this Performance Data to understand aggregate usage patterns and make our products more useful to you. The Performance Data is collected by Couchbase when you access the Admin Console in the configuration wizard if this checkbox is selected. You may turn this feature off at any time from the Admin Console settings page. You can find out more about what data is collected and how it is used if you choose to keep this checkbox enabled in the privacy FAQ (link below), which supplements Couchbase&apos;s privacy policy (link below).'
                    }
                  />

                  <a
                    rel="noopener noreferrer"
                    href={`https://docs.couchbase.com/server/${majorMinorVersion}/product-privacy-faq.html`}
                    target="_blank"
                    className="text-smaller margin-right-1"
                  >
                    Privacy FAQ
                  </a>
                  <a
                    rel="noopener noreferrer"
                    href="https://www.couchbase.com/privacy-policy"
                    target="_blank"
                    className="text-smaller"
                  >
                    Couchbase Privacy Policy
                  </a>
                </div>

                <FieldControl
                  strict={false}
                  name="enableStats"
                  render={({ handler }) => (
                    <>
                      <input
                        type="checkbox"
                        id="init-notifications-updates-enabled"
                        disabled={!isEnterprise}
                        defaultChecked
                        {...handler()}
                      />
                      <label
                        className="text-small"
                        htmlFor="init-notifications-updates-enabled"
                        disabled={!isEnterprise}
                      >
                        Share usage information and get software update
                        notifications.
                      </label>
                    </>
                  )}
                />
              </div>

              <div className="panel-footer">
                <UISref
                  to="app.wizard.setupNewCluster"
                  options={{ location: false }}
                >
                  <a className="tight">&lt; Back</a>
                </UISref>
                <span>
                  <OverlayTrigger placement="top" overlay={tipContent}>
                    <button
                      type="button"
                      className="outline tight margin-right-quarter"
                      onClick={() => this.defaultForm.submit.next(true)}
                    >
                      Finish With Defaults
                    </button>
                  </OverlayTrigger>
                  <button
                    type="submit"
                    className="tight margin-left-0"
                    ref={(input) => {
                      this.input = input;
                    }}
                  >
                    Configure Disk, Memory, Services
                  </button>
                </span>
              </div>
            </form>
          )}
        />
      </div>
    );
  }
}

export { MnWizardTermsAndConditionsComponent };
