/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { map, withLatestFrom, first, filter, startWith } from 'rxjs/operators';
import { pipe, combineLatest, Subject } from 'rxjs';
import { clone } from 'ramda';

import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnWizardService } from './mn.wizard.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnFormService } from './mn.form.service.js';
import { MnAuthService } from './mn.auth.service.js';
import { MnAdminService } from './mn.admin.service.js';
import mnPools from 'components/mn_pools';
import { UIRouter as uiRouter } from 'mn.react.router';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import { MnHostnameConfigComponent } from './mn.hostname.config.component.jsx';
import { MnServicesConfigComponent } from './mn.services.config.component.jsx';
import { MnStorageModeComponent } from './mn.storage.mode.component.jsx';
import { MnNodeStorageConfigComponent } from './mn.node.storage.config.component.jsx';
import { FieldGroup, FieldControl } from 'react-reactive-form';
import { UISref } from '@uirouter/react';

class MnWizardNewClusterConfigComponent extends MnLifeCycleHooksToStream {
  constructor() {
    super();
    this.state = {
      memoryQuotasFirst: null,
      postClusterInitHttpError: null,
      servicesHttpError: null,
      totalRAMMegs: null,
      maxRAMMegs: null,
      isEnterprise: null,
      isButtonDisabled: null,
      majorMinorVersion: null,
    };
  }

  componentWillMount() {
    this.postClusterInitHttp = MnWizardService.stream.postClusterInitHttp;
    this.majorMinorVersion = MnAdminService.stream.majorMinorVersion;

    this.wizardForm = MnWizardService.wizardForm;
    this.newClusterConfigForm = MnWizardService.wizardForm.newClusterConfig;
    this.getServicesValues =
      MnWizardService.getServicesValues.bind(MnWizardService);

    this.totalRAMMegs = MnWizardService.stream.totalRAMMegs;
    this.maxRAMMegs = MnWizardService.stream.maxRAMMegs;
    this.memoryQuotasFirst = MnWizardService.stream.memoryQuotasFirst;

    this.servicesHttp = MnWizardService.stream.servicesHttp;
    this.groupHttp = MnWizardService.stream.groupHttp;

    this.isEnterprise = MnPoolsService.stream.isEnterprise;

    this.postClusterInitHttpError = this.postClusterInitHttp.error;
    this.servicesHttpError = this.servicesHttp.error;

    MnHelperReactService.async(this, 'postClusterInitHttpError');
    MnHelperReactService.async(this, 'majorMinorVersion');
    MnHelperReactService.async(this, 'totalRAMMegs');
    MnHelperReactService.async(this, 'maxRAMMegs');
    MnHelperReactService.async(this, 'memoryQuotasFirst');
    MnHelperReactService.async(this, 'servicesHttpError');
    MnHelperReactService.async(this, 'isEnterprise');

    let postPoolsDefaultErrors =
      MnAdminService.stream.postPoolsDefaultValidation.error.pipe(
        map((error) => error && !!Object.keys(error.errors).length),
        startWith(false)
      );

    let hostConfigField = this.wizardForm.newClusterConfig.get(
      'clusterStorage.hostConfig'
    );
    this.hostConfigField = hostConfigField;

    const statusChanges = new Subject();
    hostConfigField.statusChanges.subscribe((v) => statusChanges.next(v));

    this.isButtonDisabled = combineLatest(
      postPoolsDefaultErrors,
      statusChanges.pipe(map((v) => v == 'INVALID'))
    ).pipe(map(([err, invalid]) => err || invalid));

    MnHelperReactService.async(this, 'isButtonDisabled');

    MnWizardService.stream.getSelfConfig
      .pipe(first())
      .subscribe((v) => MnWizardService.setSelfConfig(v));

    this.form = MnFormService.create(this);

    MnPoolsService.stream.isEnterprise.pipe(first()).subscribe(() => {
      this.form
        .setPackPipe(
          pipe(
            filter(() => hostConfigField.valid),
            withLatestFrom(MnPoolsService.stream.isEnterprise),
            map(this.getClusterInitConfig.bind(this))
          )
        )
        .setPostRequest(MnWizardService.stream.postClusterInitHttp);

      /** We need to check for err === 0 for certificate specific errors
       *  when using TLS. Certificates are regenerated during the middle
       *  of postClusterInitHttp, which causes postUILogin to error or
       *  more specifically, timeout.
       */
      this.form
        .setPackPipe(map(MnWizardService.getUserCreds.bind(MnWizardService)))
        .setPostRequest(MnAuthService.stream.postUILogin)
        .clearErrors()
        .showGlobalSpinner()
        .error((err) => {
          if (err === 0) {
            window.location.reload();
          }
        })
        .success(() => {
          MnHelperReactService.mnGlobalSpinnerFlag.next(true);
          mnPools.clearCache();
          uiRouter.urlRouter.sync();
        });
    });
  }

  componentWillUnmount() {
    super.componentWillUnmount();
    this.hostConfigField.statusChanges.unsubscribe();
  }

  getAddressFamily(addressFamilyUI) {
    switch (addressFamilyUI) {
      case 'inet':
      case 'inetOnly':
        return 'ipv4';
      case 'inet6':
      case 'inet6Only':
        return 'ipv6';
      default:
        return 'ipv4';
    }
  }

  getAddressFamilyOnly(addressFamilyUI) {
    switch (addressFamilyUI) {
      case 'inet':
      case 'inet6':
        return false;
      case 'inetOnly':
      case 'inet6Only':
        return true;
      default:
        return false;
    }
  }

  getHostConfig() {
    let clusterStore = this.wizardForm.newClusterConfig.get('clusterStorage');

    return {
      afamily: this.getAddressFamily(
        clusterStore.get('hostConfig.addressFamilyUI').value
      ),
      afamilyOnly: this.getAddressFamilyOnly(
        clusterStore.get('hostConfig.addressFamilyUI').value
      ),
      nodeEncryption: clusterStore.get('hostConfig.nodeEncryption').value
        ? 'on'
        : 'off',
    };
  }

  getIndexesConfig() {
    var rv = {};
    if (this.wizardForm.newClusterConfig.get('services.flag').value.index) {
      rv.indexerStorageMode =
        this.wizardForm.newClusterConfig.get('storageMode').value;
    }
    return rv;
  }

  getClusterInitConfig([, isEnterprise]) {
    let rv = {};
    let nodeStorage = this.wizardForm.newClusterConfig.get('clusterStorage');
    rv.hostname = nodeStorage.get('hostname').value;
    rv.dataPath = nodeStorage.get('storage.path').value;
    rv.indexPath = nodeStorage.get('storage.index_path').value;
    rv.eventingPath = nodeStorage.get('storage.eventing_path').value;
    rv.sendStats = this.wizardForm.termsAndConditions.get('enableStats').value;
    let services = this.wizardForm.newClusterConfig.get('services.flag');
    rv.services = this.getServicesValues(services).join(',');
    let userData = clone(this.wizardForm.newCluster.value.user);
    delete userData.passwordVerify;
    userData.port = 'SAME';

    let hostConfigRv = {};

    if (isEnterprise) {
      rv.analyticsPath = nodeStorage.get('storage.cbas_path').value;
      rv.javaHome = this.wizardForm.newClusterConfig.get('javaPath').value;
      hostConfigRv = this.getHostConfig.bind(this)();
    }

    let poolsDefaultRv = this.getPoolsDefaultValues.bind(this)(isEnterprise);
    let indexesRv = this.getIndexesConfig.bind(this)();

    return Object.assign(rv, poolsDefaultRv, hostConfigRv, indexesRv, userData);
  }

  getPoolsDefaultValues(isEnterprise) {
    var services = [
      ['memoryQuota', 'kv'],
      ['indexMemoryQuota', 'index'],
      ['ftsMemoryQuota', 'fts'],
      ['queryMemoryQuota', 'n1ql'],
    ];
    if (isEnterprise) {
      services.push(['eventingMemoryQuota', 'eventing']);
      services.push(['cbasMemoryQuota', 'cbas']);
    }
    return services.reduce(this.getPoolsDefaultValue.bind(this), {
      clusterName: this.wizardForm.newCluster.get('clusterName').value,
    });
  }

  getPoolsDefaultValue(result, names) {
    var service = this.wizardForm.newClusterConfig.get(
      'services.flag.' + names[1]
    );
    if (service && service.value) {
      result[names[0]] = this.wizardForm.newClusterConfig.get(
        'services.field.' + names[1]
      ).value;
    }
    return result;
  }

  render() {
    const {
      memoryQuotasFirst,
      postClusterInitHttpError,
      servicesHttpError,
      totalRAMMegs,
      maxRAMMegs,
      isEnterprise,
      isButtonDisabled,
      majorMinorVersion,
    } = this.state;

    if (
      !this.newClusterConfigForm.get('services').get('flag') ||
      !this.newClusterConfigForm.get('services').get('field')
    ) {
      return null;
    }

    const tipContent_serviceMem = (
      <Tooltip>
        <p>
          Memory quotas let Couchbase manage its memory usage between different
          services without running out of memory or degrading performance. The
          DATA SERVICE quota, for instance, is the allocation of physical RAM
          you want to set aside for storing your data in Couchbase Server. Other
          services like INDEXING use their memory allocations in different ways.
        </p>
        <p>THE DEFAULTS ARE A SAFE PLACE TO START.</p>
        <a
          href={`https://docs.couchbase.com/server/${majorMinorVersion}/learn/buckets-memory-and-storage/memory.html`}
          target="_blank"
          rel="noopener noreferrer"
          className="block margin-bottom-1"
        >
          Learn more about memory quotas for Couchbase services.
        </a>
      </Tooltip>
    );

    return (
      <div className="panel dialog-med dialog dialog-wizard height-85vh">
        <div className="panel-header flex-left margin-bottom-quarter">
          <img
            src="./cb_logo_bug_white_2.svg"
            width="32"
            height="32"
            className="margin-right-half"
          />
          <h2>Couchbase &gt; New Cluster &gt; Configure</h2>
        </div>

        <FieldGroup
          strict={false}
          control={this.newClusterConfigForm}
          render={() => (
            <form
              className="forms"
              style={{ height: 'inherit' }}
              onSubmit={(e) => {
                e.preventDefault();
                this.form.submit.next();
                this.newClusterConfigForm.handleSubmit();
              }}
              noValidate
            >
              <div
                style={{ height: 'calc(100% - 112px)', overflow: 'auto' }}
                className="show-scrollbar"
              >
                <div className="panel-content">
                  <div
                    className="error"
                    hidden={!postClusterInitHttpError?.errors?._}
                  >
                    {postClusterInitHttpError?.errors?._}
                  </div>

                  <MnHostnameConfigComponent
                    isHostCfgEnabled={true}
                    group={this.newClusterConfigForm.get('clusterStorage')}
                  />

                  <div className="formrow">
                    <div className="row formrow">
                      <span className="row flex-left">
                        <label className="margin-right-quarter">
                          Service Memory Quotas
                        </label>
                        <OverlayTrigger
                          placement="right"
                          delay={{ hide: 2000 }}
                          overlay={tipContent_serviceMem}
                        >
                          <span className="fa-stack icon-info">
                            <span className="icon fa-circle-thin fa-stack-2x"></span>
                            <span className="icon fa-info fa-stack-1x"></span>
                          </span>
                        </OverlayTrigger>
                      </span>
                      <small className="text-smaller">
                        Per service / per node
                      </small>
                    </div>

                    <div>
                      <div
                        className="error error-form"
                        hidden={!servicesHttpError}
                      >
                        {servicesHttpError &&
                          servicesHttpError.map((error, i) => (
                            <div key={i}>{error}</div>
                          ))}
                      </div>

                      <MnServicesConfigComponent
                        isFieldEnabled={true}
                        isFlagEnabled={true}
                        initDataStream={this.memoryQuotasFirst}
                        group={this.newClusterConfigForm.get('services')}
                      />

                      <div className="content-box text-center margin-top-1">
                        <strong>RAM Available</strong> {totalRAMMegs}MiB &nbsp;
                        <strong>Max Allowed Quota</strong> {maxRAMMegs}MiB
                      </div>

                      <label>Index Storage Setting</label>
                      <MnStorageModeComponent
                        indexFlag={this.newClusterConfigForm.get(
                          'services.flag.index'
                        )}
                        control={this.newClusterConfigForm.get('storageMode')}
                      />

                      <MnNodeStorageConfigComponent
                        group={this.newClusterConfigForm.get('clusterStorage')}
                      />

                      {isEnterprise && (
                        <div className="formrow">
                          <div className="row">
                            <label htmlFor="setup_java_runtime_path_input">
                              Java Runtime Path
                            </label>
                            <small className="text-smaller">optional</small>
                          </div>
                          <FieldControl
                            name="javaPath"
                            render={({ handler }) => (
                              <input
                                type="text"
                                id="setup_java_runtime_path_input"
                                autoCorrect="off"
                                spellCheck="false"
                                autoCapitalize="off"
                                {...handler()}
                              />
                            )}
                          />
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <div className="panel-footer scroll-shadow margin-top-quarter">
                <UISref
                  to="app.wizard.termsAndConditions"
                  options={{ location: false }}
                >
                  <a>&lt; Back</a>
                </UISref>
                <button disabled={isButtonDisabled} type="submit">
                  Save & Finish
                </button>
              </div>
            </form>
          )}
        />
      </div>
    );
  }
}

export { MnWizardNewClusterConfigComponent };
