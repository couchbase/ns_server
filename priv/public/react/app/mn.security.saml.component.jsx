import React from 'react';
import { MnLifeCycleHooksToStream } from 'mn.core';
import { UIRouter } from 'mn.react.router';
import { filter, map, distinctUntilChanged, takeUntil } from 'rxjs/operators';
import { combineLatest, merge, pipe } from 'rxjs';
import { FieldGroup, FieldControl } from 'react-reactive-form';
import { MnFormService } from './mn.form.service.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnSecurityService } from './mn.security.service.js';

import MnPermissions from './components/mn_permissions.js';
import { MnPoolsService } from './mn.pools.service.js';
import MnAlerts from './components/mn_alerts.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { MnSpinner } from './components/directives/mn_spinner.jsx';
import { clone } from 'ramda';
import MnFileReader from './components/mn_file_reader.jsx';
import CopyToClipboard from 'react-copy-to-clipboard';

export class MnSecuritySamlComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      samlData: null,
      samlError: null,
      samlValidationError: null,
      isEnterprise: null,
      permissionsAdminSecurityWrite: null,
      httpError: null,
      postSamlGlobalError: null,
      formLoading: false,
      enabled: false,
      showServiceProviderMetaDataState: false,
      showKeyAndCertificatesState: false,
      showIdentityProviderMetaDataState: false,
      showTrustedFingerprintsState: false,
      showSingleSignOnState: false,
      showAdvancedState: false,
      serviceProviderMetaDataHasErrors: false,
      showKeyAndCertificatesHasErrors: false,
      showIdentityProviderMetaDataHasErrors: false,
      showTrustedFingerprintsHasErrors: false,
      showSingleSignOnHasErrors: false,
      showAdvancedHasErrors: false,
      hasRemotePeerWarning: false,
      hasSignatureWarning: false,
    };

    this.cancel = this.cancel.bind(this);
    this.setIdpMetadata = this.setIdpMetadata.bind(this);
    this.setSpKey = this.setSpKey.bind(this);
    this.setSpCertificate = this.setSpCertificate.bind(this);
    this.setSpChain = this.setSpChain.bind(this);
    this.setIdpMetadataTLSCAs = this.setIdpMetadataTLSCAs.bind(this);
    this.setSpTrustedFingerprints = this.setSpTrustedFingerprints.bind(this);
    this.handleSubmit = this.handleSubmit.bind(this);
  }

  handleSubmit(e) {
    e.preventDefault();
    this.form.submit.next();
  }

  handleCopy(_, result) {
    if (result) {
      this.mnAlerts.formatAndSetAlerts(
        'URL copied successfully!',
        'success',
        2500
      );
    } else {
      this.mnAlerts.formatAndSetAlerts('Unable to copy URL!', 'error', 2500);
    }
  }

  componentDidMount() {
    this.mnHelperService = MnHelperService;
    this.mnAlerts = MnAlerts;

    this.getSaml = MnSecurityService.stream.getSaml;
    this.postSaml = MnSecurityService.stream.postSaml;
    this.postSamlValidation = MnSecurityService.stream.postSamlValidation;
    this.isEnterprise = MnPoolsService.stream.isEnterprise;

    this.permissionsAdminSecurityWrite = MnPermissions.stream.pipe(
      map(
        (permissions) =>
          permissions.cluster.admin.security.external.write ||
          permissions.cluster.admin.users.external.write
      )
    );
    MnHelperReactService.async(this, 'permissionsAdminSecurityWrite');

    this.form = MnFormService.create(this);
    this.form
      .setFormGroup({
        authnNameIDFormat: null,
        enabled: null,
        groupsAttribute: null,
        groupsAttributeSep: null,
        groupsFilterRE: null,
        idpAuthnBinding: null,
        idpLogoutBinding: null,
        idpMetadata: null,
        idpMetadataURL: null,
        idpMetadataConnectAddressFamily: null,
        idpMetadataHttpTimeoutMs: null,
        idpMetadataOrigin: null,
        idpMetadataRefreshIntervalS: null,
        idpMetadataTLSCAs: null,
        idpMetadataTLSExtraOpts: null,
        idpMetadataTLSSNI: null,
        idpMetadataTLSVerifyPeer: null,
        idpSignsMetadata: null,
        rolesAttribute: null,
        rolesAttributeSep: null,
        rolesFilterRE: null,
        singleLogoutEnabled: null,
        spAssertionDupeCheck: null,
        spBaseURLScheme: null,
        spBaseURLType: null,
        spCertificate: null,
        spChain: null,
        spConsumeURL: null,
        spContactEmail: null,
        spContactName: null,
        spCustomBaseURL: null,
        spEntityId: null,
        spKey: null,
        spLogoutURL: null,
        spMetadataCacheDuration: null,
        spMetadataURL: null,
        spOrgDisplayName: null,
        spOrgName: null,
        spOrgURL: null,
        spSessionExpire: null,
        spSignMetadata: null,
        spSignRequests: null,
        spVerifyIssuer: null,
        spTrustedFingerprints: null,
        spTrustedFingerprintsUsage: null,
        spVerifyAssertionEnvelopSig: null,
        spVerifyAssertionSig: null,
        spVerifyLogoutReqSig: null,
        spVerifyRecipient: null,
        spVerifyRecipientValue: null,
        usernameAttribute: null,

        // FE only form controls
        idpMetadataRefreshIntervalSFlag: null,
        spVerifyRecipientFlag: null,
        usernameAttributeFlag: null,
        groupsAttributeFlag: null,
        rolesAttributeFlag: null,
        spAssertionDupeCheckFlag: null,
        spTrustedFingerprintsUsageMetadata: null,
        spTrustedFingerprintsUsageEverything: null,
      })
      .setUnpackPipe(pipe(map(this.unpackGetSaml.bind(this))))
      .setPackPipe(pipe(map(this.packPostSaml.bind(this))))
      .setSource(this.getSaml)
      .setPostRequest(this.postSaml)
      .setValidation(
        this.postSamlValidation,
        MnPermissions.stream.pipe(
          map(
            (permissions) =>
              permissions.cluster.admin.security.external.write ||
              permissions.cluster.admin.users.external.write
          )
        )
      )
      .showGlobalSpinner()
      .successMessage('SAML settings saved successfully!')
      .clearErrors()
      .success(() => {
        this.form.setSource(this.getSaml);
      });

    this.form.group.disable();

    this.formLoading = this.form.loadingPipe;
    MnHelperReactService.async(this, 'formLoading');

    this.httpError = merge(this.postSaml.error, this.postSamlValidation.error);
    MnHelperReactService.async(this, 'httpError');

    // Possible to receive a 500 error in the form of a single value array.
    this.postSamlGlobalError = this.httpError.pipe(
      map((error) => {
        if (error && Array.isArray(error)) {
          return error[0];
        }
      })
    );
    MnHelperReactService.async(this, 'postSamlGlobalError');

    this.enabled = MnHelperReactService.valueChanges(
      this,
      this.form.group.get('enabled').valueChanges
    ).pipe(distinctUntilChanged());
    MnHelperReactService.async(this, 'enabled');

    // Toggle Streams.
    this.showServiceProviderMetaData = this.mnHelperService.createToggle();
    this.showServiceProviderMetaDataState =
      this.showServiceProviderMetaData.state;
    MnHelperReactService.async(this, 'showServiceProviderMetaDataState');

    this.showKeyAndCertificates = this.mnHelperService.createToggle();
    this.showKeyAndCertificatesState = this.showKeyAndCertificates.state;
    MnHelperReactService.async(this, 'showKeyAndCertificatesState');

    this.showIdentityProviderMetaData = this.mnHelperService.createToggle();
    this.showIdentityProviderMetaDataState =
      this.showIdentityProviderMetaData.state;
    MnHelperReactService.async(this, 'showIdentityProviderMetaDataState');

    this.showTrustedFingerprints = this.mnHelperService.createToggle();
    this.showTrustedFingerprintsState = this.showTrustedFingerprints.state;
    MnHelperReactService.async(this, 'showTrustedFingerprintsState');

    this.showSingleSignOn = this.mnHelperService.createToggle();
    this.showSingleSignOnState = this.showSingleSignOn.state;
    MnHelperReactService.async(this, 'showSingleSignOnState');

    this.showAdvanced = this.mnHelperService.createToggle();
    this.showAdvancedState = this.showAdvanced.state;
    MnHelperReactService.async(this, 'showAdvancedState');

    // Error Streams.
    this.showServiceProviderMetaDataHasErrors = combineLatest(
      this.enabled,
      this.httpError
    ).pipe(
      filter(([_, errors]) => !!errors),
      map(this.showServiceProviderMetaDataHasErrors.bind(this))
    );
    MnHelperReactService.async(this, 'showServiceProviderMetaDataHasErrors');

    this.showKeyAndCertificatesHasErrors = combineLatest(
      this.enabled,
      this.httpError
    ).pipe(
      filter(([_, errors]) => !!errors),
      map(this.showKeyAndCertificatesHasErrors.bind(this))
    );
    MnHelperReactService.async(this, 'showKeyAndCertificatesHasErrors');

    this.showIdentityProviderMetaDataHasErrors = combineLatest(
      this.enabled,
      this.httpError
    ).pipe(
      filter(([_, errors]) => !!errors),
      map(this.showIdentityProviderMetaDataHasErrors.bind(this))
    );
    MnHelperReactService.async(this, 'showIdentityProviderMetaDataHasErrors');

    this.showTrustedFingerprintsHasErrors = combineLatest(
      this.enabled,
      this.httpError
    ).pipe(
      filter(([_, errors]) => !!errors),
      map(this.showTrustedFingerprintsHasErrors.bind(this))
    );
    MnHelperReactService.async(this, 'showTrustedFingerprintsHasErrors');

    this.showSingleSignOnHasErrors = combineLatest(
      this.enabled,
      this.httpError
    ).pipe(
      filter(([_, errors]) => !!errors),
      map(this.showSingleSignOnHasErrors.bind(this))
    );
    MnHelperReactService.async(this, 'showSingleSignOnHasErrors');

    this.showAdvancedHasErrors = combineLatest(
      this.enabled,
      this.httpError
    ).pipe(
      filter(([_, errors]) => !!errors),
      map(this.showAdvancedHasErrors.bind(this))
    );
    MnHelperReactService.async(this, 'showAdvancedHasErrors');

    // Disabled Streams.
    combineLatest([this.enabled, this.permissionsAdminSecurityWrite])
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableForm.bind(this));

    this.subscribeMaybeDisableField(
      'idpMetadataTLSVerifyPeer',
      'idpMetadataTLSCAs'
    );
    this.subscribeMaybeDisableField(
      'idpMetadataRefreshIntervalSFlag',
      'idpMetadataRefreshIntervalS'
    );
    this.subscribeMaybeDisableField(
      'usernameAttributeFlag',
      'usernameAttribute'
    );
    this.subscribeMaybeDisableField('groupsAttributeFlag', 'groupsAttribute');
    this.subscribeMaybeDisableField(
      'groupsAttributeFlag',
      'groupsAttributeSep'
    );
    this.subscribeMaybeDisableField('groupsAttributeFlag', 'groupsFilterRE');
    this.subscribeMaybeDisableField('rolesAttributeFlag', 'rolesAttribute');
    this.subscribeMaybeDisableField('rolesAttributeFlag', 'rolesAttributeSep');
    this.subscribeMaybeDisableField('rolesAttributeFlag', 'rolesFilterRE');

    MnHelperReactService.valueChanges(
      this,
      this.form.group.get('spTrustedFingerprintsUsageEverything').valueChanges
    )
      .pipe(
        distinctUntilChanged(),
        map((v) => !v),
        takeUntil(this.mnOnDestroy)
      )
      // Conversion TODO: OnPrem has a bug where this throws a (silent)
      // error. It's not really a big deal, since it relates to turning off a field that gets hidden anyway.
      .subscribe(
        this.maybeDisableField.bind(this, 'spTrustedFingerprintsUsageMetadata')
      );

    // Warning streams.
    this.hasRemotePeerWarning = combineLatest([
      MnHelperReactService.valueChanges(
        this,
        this.form.group.get('idpMetadataTLSVerifyPeer').valueChanges
      ),
      MnHelperReactService.valueChanges(
        this,
        this.form.group.get('spTrustedFingerprintsUsage').valueChanges
      ),
    ])
      .pipe(
        map(this.hasRemotePeerWarning.bind(this)),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe((hasWarning) =>
        this.setState({ hasRemotePeerWarning: hasWarning })
      );

    this.hasSignatureWarning = combineLatest([
      MnHelperReactService.valueChanges(
        this,
        this.form.group.get('spVerifyAssertionSig').valueChanges
      ),
      MnHelperReactService.valueChanges(
        this,
        this.form.group.get('spVerifyAssertionEnvelopSig').valueChanges
      ),
    ])
      .pipe(
        map(this.hasSignatureWarning.bind(this)),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe((hasWarning) =>
        this.setState({ hasSignatureWarning: hasWarning })
      );
  }

  subscribeMaybeDisableField(flag, field) {
    combineLatest([
      MnHelperReactService.valueChanges(
        this,
        this.form.group.get(flag).valueChanges
      ),
      this.enabled,
    ])
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableField.bind(this, field));
  }

  packPostSaml() {
    const packedData = clone(this.form.group.value);

    if (!packedData.enabled) {
      return {
        enabled: false,
      };
    }

    // Read only values.
    delete packedData.spConsumeURL;
    delete packedData.spLogoutURL;
    delete packedData.spMetadataURL;
    delete packedData.idpMetadataTLSExtraOpts;

    if (!packedData.usernameAttributeFlag) {
      packedData.usernameAttribute = '';
    }
    delete packedData.usernameAttributeFlag;

    if (!packedData.groupsAttributeFlag) {
      packedData.groupsAttribute = '';
    }
    delete packedData.groupsAttributeFlag;

    if (!packedData.rolesAttributeFlag) {
      packedData.rolesAttribute = '';
    }
    delete packedData.rolesAttributeFlag;

    if (packedData.idpMetadataOrigin === 'http') {
      delete packedData.idpMetadata;
    } else {
      delete packedData.idpMetadataURL;
    }

    if (!packedData.idpMetadataRefreshIntervalSFlag) {
      delete packedData.idpMetadataRefreshIntervalS;
    }
    if (
      packedData.idpMetadataOrigin === 'http' &&
      !packedData.idpMetadataRefreshIntervalSFlag
    ) {
      packedData.idpMetadataOrigin = 'http_one_time';
    }
    delete packedData.idpMetadataRefreshIntervalSFlag;

    if (!packedData.spKey || packedData.spKey === '**********') {
      delete packedData.spKey;
    }

    if (!packedData.spCertificate) {
      delete packedData.spCertificate;
    }

    if (packedData.spVerifyRecipientFlag === false) {
      packedData.spVerifyRecipient = false;
    }
    delete packedData.spVerifyRecipientFlag;

    if (packedData.spAssertionDupeCheckFlag === false) {
      packedData.spAssertionDupeCheck = 'disabled';
    }
    delete packedData.spAssertionDupeCheckFlag;

    if (packedData.spTrustedFingerprints == '') {
      delete packedData.spTrustedFingerprints;
    }

    if (packedData.spTrustedFingerprints == '') {
      delete packedData.spTrustedFingerprints;
    }

    if (packedData.spTrustedFingerprintsUsageMetadata === true) {
      packedData.spTrustedFingerprintsUsage = 'metadataInitialOnly';
    }

    if (packedData.spTrustedFingerprintsUsageEverything === true) {
      packedData.spTrustedFingerprintsUsage = 'everything';
    }

    if (
      packedData.spTrustedFingerprintsUsageMetadataOnly === false &&
      packedData.spTrustedFingerprintsUsageEverything === false
    ) {
      packedData.spTrustedFingerprintsUsage = 'metadataOnly';
    }

    if (packedData.spBaseURLType !== 'custom') {
      delete packedData.spCustomBaseURL;
    }

    if (packedData.spVerifyRecipient !== 'custom') {
      delete packedData.spVerifyRecipientValue;
    }

    delete packedData.spTrustedFingerprintsUsageEverything;
    delete packedData.spTrustedFingerprintsUsageMetadata;

    return packedData;
  }

  unpackGetSaml(data) {
    let unpackedData = clone(data);

    if (unpackedData.usernameAttribute) {
      unpackedData.usernameAttributeFlag = true;
    }

    if (unpackedData.groupsAttribute) {
      unpackedData.groupsAttributeFlag = true;
    }

    if (unpackedData.rolesAttribute) {
      unpackedData.rolesAttributeFlag = true;
    }

    if (unpackedData.idpMetadataOrigin === 'http') {
      unpackedData.idpMetadataRefreshIntervalSFlag = true;
    }
    if (unpackedData.idpMetadataOrigin === 'http_one_time') {
      unpackedData.idpMetadataOrigin = 'http';
      unpackedData.idpMetadataRefreshIntervalSFlag = false;
    }

    if (unpackedData.spVerifyRecipient) {
      unpackedData.spVerifyRecipientFlag = true;
    } else {
      unpackedData.spVerifyRecipientFlag = false;
      unpackedData.spVerifyRecipient = 'consumeURL'; //default when flag is enabled
    }

    if (unpackedData.spAssertionDupeCheck === 'disabled') {
      unpackedData.spAssertionDupeCheckFlag = false;
      unpackedData.spAssertionDupeCheck = 'global'; //default when flag is enabled
    } else {
      unpackedData.spAssertionDupeCheckFlag = true;
    }

    if (unpackedData.spTrustedFingerprintsUsage === 'metadataInitialOnly') {
      unpackedData.spTrustedFingerprintsUsageMetadata = true;
    }

    if (unpackedData.spTrustedFingerprintsUsage === 'everything') {
      unpackedData.spTrustedFingerprintsUsageEverything = true;
    }

    return unpackedData;
  }
  showServiceProviderMetaDataHasErrors([enabled, errors]) {
    const errorKeys = [
      'spEntityId',
      'spOrgName',
      'spContactName',
      'spOrgDisplayName',
      'spContactEmail',
      'spOrgURL',
      'spBaseURLType',
      'spBaseURLScheme',
      'spSignMetadata',
      'spCustomBaseURL',
    ];

    return enabled && this.hasKeyErrors(errorKeys, errors);
  }

  showKeyAndCertificatesHasErrors([enabled, errors]) {
    const errorKeys = ['spKey', 'spCertificate', 'spChain'];
    return enabled && this.hasKeyErrors(errorKeys, errors);
  }

  showIdentityProviderMetaDataHasErrors([enabled, errors]) {
    const errorKeys = [
      'idpMetadata',
      'idpMetadataURL',
      'idpMetadataOrigin',
      'idpMetadataRefreshIntervalS',
      'idpMetadataTLSVerifyPeer',
    ];

    return enabled && this.hasKeyErrors(errorKeys, errors);
  }

  showTrustedFingerprintsHasErrors([enabled, errors]) {
    const errorKeys = ['spTrustedFingerprints', 'spTrustedFingerprintsUsage'];
    return enabled && this.hasKeyErrors(errorKeys, errors);
  }

  showSingleSignOnHasErrors([enabled, errors]) {
    const errorKeys = ['authnNameIDFormat'];
    return enabled && this.hasKeyErrors(errorKeys, errors);
  }

  showAdvancedHasErrors([enabled, errors]) {
    const errorKeys = ['spMetadataCacheDuration', 'idpMetadataHttpTimeoutMs'];
    return enabled && this.hasKeyErrors(errorKeys, errors);
  }

  hasKeyErrors(errorKeys, errors) {
    if (errors && Array.isArray(errors.errors)) {
      return false;
    }
    return Object.keys(errors.errors).some((error) =>
      errorKeys.includes(error)
    );
  }

  maybeDisableForm([enabled, writePermission]) {
    const method = enabled && writePermission ? 'enable' : 'disable';
    const settings = { emitEvent: false };

    this.form.group[method](settings);

    if (writePermission) {
      this.form.group.get('enabled').enable();
    }
  }

  maybeDisableField(field, [fieldEnable, formEnabled]) {
    this.form.group
      .get(field)
      [fieldEnable && formEnabled ? 'enable' : 'disable']({ emitEvent: false });
  }

  hasRemotePeerWarning([verifyPeer, fingerprintUsage]) {
    return !verifyPeer && fingerprintUsage != 'everything';
  }

  hasSignatureWarning([assertSig, assertEnvSig]) {
    return !assertSig && !assertEnvSig;
  }

  cancel() {
    UIRouter.stateService.reload('app.admin.security.saml');
  }

  // File reader handlers
  setIdpMetadata(value) {
    this.form.group.get('idpMetadata').setValue(value);
  }

  setSpKey(value) {
    this.form.group.get('spKey').setValue(value);
  }

  setSpCertificate(value) {
    this.form.group.get('spCertificate').setValue(value);
  }

  setSpChain(value) {
    this.form.group.get('spChain').setValue(value);
  }

  setIdpMetadataTLSCAs(value) {
    this.form.group.get('idpMetadataTLSCAs').setValue(value);
  }

  setSpTrustedFingerprints(value) {
    this.form.group.get('spTrustedFingerprints').setValue(value);
  }

  render() {
    const { httpError, permissionsAdminSecurityWrite, formLoading } =
      this.state;

    if (formLoading || !this.form) {
      return <MnSpinner mnSpinner={true} />;
    }

    return (
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <h3 className="margin-bottom-half">SAML Configuration</h3>
        <p className="max-width-9" style={{ marginBottom: 0 }}>
          SAML (Security Assertion Markup Language) is an XML-based standard
          used for exchanging user authentication, and attribute information
          between different parties, such as identity provider (IDP) and a
          service provider (SP). It enables single sign-on (SSO) and allows
          users to access different applications or websites without logging in
          multiple times.
        </p>

        <div className="error" hidden={!this.state.postSaml?.error?.errors?._}>
          {this.state.postSaml?.error?.errors?._}
        </div>

        <div className="error" hidden={!this.state.postSamlGlobalError}>
          {this.state.postSaml?.error}
        </div>

        <FieldGroup
          strict={false}
          control={this.form.group}
          render={({ get }) => (
            <form onSubmit={this.handleSubmit} className="forms">
              <div className="formrow">
                <div className="row flex-left margin-top-2 margin-bottom-2">
                  <label className="toggle-control margin-0">
                    <FieldControl
                      name="enabled"
                      strict={false}
                      render={({ handler }) => (
                        <input type="checkbox" {...handler('checkbox')} />
                      )}
                    />
                    <span className="toggle-control-body"></span>
                  </label>
                  <span className="text-small bold">&nbsp; Enabled</span>
                </div>
              </div>
              <div hidden={!get('spMetadataURL')?.value}>
                <span className="inline">Current SP metadata URL:</span>
                <span className="inline margin-left-1">
                  {get('spMetadataURL')?.value}
                </span>
                <span className="inline nowrap margin-left-1">
                  <CopyToClipboard
                    text={get('spMetadataURL')?.value}
                    onCopy={this.handleCopy}
                  >
                    <a>
                      Copy URL <span className="icon fa-clipboard"></span>
                    </a>
                  </CopyToClipboard>
                  <a
                    className="margin-left-1"
                    href={get('spMetadataURL')?.value}
                  >
                    Download Metadata <span className="icon fa-download"></span>
                  </a>
                </span>
              </div>

              <div hidden={!get('spConsumeURL')?.value}>
                <span className="inline">Current SP consume URL:</span>
                <span className="inline margin-left-1">
                  {get('spConsumeURL')?.value}
                </span>
                <span className="inline nowrap margin-left-1">
                  <CopyToClipboard
                    text={get('spConsumeURL')?.value}
                    onCopy={this.handleCopy}
                  >
                    <a>
                      Copy URL <span className="icon fa-clipboard"></span>
                    </a>
                  </CopyToClipboard>
                </span>
              </div>

              <div
                hidden={!get('spLogoutURL')?.value}
                className="margin-bottom-2"
              >
                <span className="inline">Current SP logout URL:</span>
                <span className="inline margin-left-1">
                  {get('spLogoutURL')?.value}
                </span>
                <span className="inline nowrap margin-left-1">
                  <CopyToClipboard
                    text={get('spLogoutURL')?.value}
                    onCopy={this.handleCopy}
                  >
                    <a>
                      Copy URL <span className="icon fa-clipboard"></span>
                    </a>
                  </CopyToClipboard>
                </span>
              </div>

              <div className="formrow">
                <h4>Service Provider Configuration</h4>
              </div>

              {/* Service Provider Metadata Section */}
              <div className="formrow">
                <span
                  className={`disclosure inline line-height-2 ${this.state.showServiceProviderMetaDataState ? 'disclosed' : ''}`}
                  onClick={() => this.showServiceProviderMetaData.click.next()}
                >
                  Metadata
                </span>{' '}
                {this.state.serviceProviderMetaDataHasErrors && (
                  <span className="error inline">
                    <span className="icon-info-warning">
                      <span className="icon fa-warning"></span>{' '}
                    </span>
                    Requires attention
                  </span>
                )}
                <div
                  hidden={!this.state.showServiceProviderMetaDataState}
                  className="margin-top-half margin-bottom-half indent-1-5 margin-bottom-1"
                >
                  <div className="formrow fix-width-8-1">
                    <FieldControl
                      name="spEntityId"
                      strict={false}
                      render={({ handler, meta, touched, hasError }) => (
                        <>
                          <label htmlFor="spEntityId_field">SP Entity ID</label>
                          <input
                            type="text"
                            id="spEntityId_field"
                            placeholder={get('spMetadataURL')?.value}
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <p className="desc">
                            As a default we use metadata URL as SP Entity ID.
                          </p>
                          <div
                            className="error"
                            hidden={!httpError?.errors?.spEntityId}
                          >
                            {httpError?.errors?.spEntityId}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="row flex-left">
                    <div className="formrow fix-width-5 margin-right-1">
                      <FieldControl
                        strict={false}
                        name="spOrgName"
                        render={({ handler }) => (
                          <>
                            <label htmlFor="orgName_field">Org Name</label>
                            <input
                              type="text"
                              id="orgName_field"
                              autoCorrect="off"
                              spellCheck="false"
                              autoCapitalize="off"
                              {...handler()}
                            />
                            <div
                              className="error"
                              hidden={!httpError?.errors?.spOrgName}
                            >
                              {httpError?.errors?.spOrgName}
                            </div>
                          </>
                        )}
                      />
                    </div>

                    <div className="formrow fix-width-5">
                      <FieldControl
                        strict={false}
                        name="spContactName"
                        render={({ handler }) => (
                          <>
                            <label htmlFor="contactName_field">
                              Contact Name
                            </label>
                            <input
                              type="text"
                              id="contactName_field"
                              autoCorrect="off"
                              spellCheck="false"
                              autoCapitalize="off"
                              {...handler()}
                            />
                            <div
                              className="error"
                              hidden={!httpError?.errors?.spContactName}
                            >
                              {httpError?.errors?.spContactName}
                            </div>
                          </>
                        )}
                      />
                    </div>
                  </div>

                  <div className="row flex-left">
                    <div className="formrow fix-width-5 margin-right-1">
                      <FieldControl
                        strict={false}
                        name="spOrgDisplayName"
                        render={({ handler }) => (
                          <>
                            <label htmlFor="orgDisplayName_field">
                              Org Display Name
                            </label>
                            <input
                              type="text"
                              id="orgDisplayName_field"
                              autoCorrect="off"
                              spellCheck="false"
                              autoCapitalize="off"
                              {...handler()}
                            />
                            <div
                              className="error"
                              hidden={!httpError?.errors?.spOrgDisplayName}
                            >
                              {httpError?.errors?.spOrgDisplayName}
                            </div>
                          </>
                        )}
                      />
                    </div>

                    <div className="formrow fix-width-5">
                      <FieldControl
                        strict={false}
                        name="spContactEmail"
                        render={({ handler }) => (
                          <>
                            <label htmlFor="contactEmail_field">
                              Contact Email
                            </label>
                            <input
                              type="text"
                              id="contactEmail_field"
                              autoCorrect="off"
                              spellCheck="false"
                              autoCapitalize="off"
                              {...handler()}
                            />
                            <div
                              className="error"
                              hidden={!httpError?.errors?.spContactEmail}
                            >
                              {httpError?.errors?.spContactEmail}
                            </div>
                          </>
                        )}
                      />
                    </div>
                  </div>

                  <div className="formrow fix-width-5 fix-width-8-1">
                    <FieldControl
                      strict={false}
                      name="spOrgURL"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="orgUrl_field">Org URL</label>
                          <input
                            type="text"
                            id="orgUrl_field"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.spOrgURL}
                          >
                            {httpError?.errors?.spOrgURL}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow">
                    <label>SP Base URL Type</label>
                    <div className="formrow checkbox-list">
                      <FieldControl
                        strict={false}
                        name="spBaseURLType"
                        render={({ handler }) => {
                          const field = handler('switch');
                          return (
                            <>
                              <input
                                {...field}
                                type="radio"
                                id="for-base-url-node"
                                value="node"
                                checked={field.value === 'node'}
                              />
                              <label htmlFor="for-base-url-node">
                                Node address
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-base-url-alternate"
                                value="alternate"
                                checked={field.value === 'alternate'}
                              />
                              <label htmlFor="for-base-url-alternate">
                                Alternate node address
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-base-url-custom"
                                value="custom"
                                checked={field.value === 'custom'}
                              />
                              <label htmlFor="for-base-url-custom">
                                Custom URL
                              </label>
                            </>
                          );
                        }}
                      />
                    </div>
                  </div>

                  <div
                    hidden={get('spBaseURLType')?.value !== 'custom'}
                    className="formrow fix-width-8-1"
                  >
                    <FieldControl
                      strict={false}
                      name="spCustomBaseURL"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="customURL">Custom URL</label>
                          <input
                            type="text"
                            id="customURL"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <p className="desc">
                            Custom URL should contain scheme host and optionally
                            port
                          </p>
                          <div
                            className="error"
                            hidden={!httpError?.errors?.spCustomBaseURL}
                          >
                            {httpError?.errors?.spCustomBaseURL}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div
                    hidden={get('spBaseURLType')?.value === 'custom'}
                    className="formrow"
                  >
                    <label>SP Base URL Scheme</label>
                    <div className="formrow checkbox-list">
                      <FieldControl
                        strict={false}
                        name="spBaseURLScheme"
                        render={({ handler }) => {
                          const field = handler('switch');
                          return (
                            <>
                              <input
                                {...field}
                                type="radio"
                                id="for-sp-base-scheme-https"
                                value="https"
                                checked={field.value === 'https'}
                              />
                              <label htmlFor="for-sp-base-scheme-https">
                                https
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-sp-base-scheme-http"
                                value="http"
                                checked={field.value === 'http'}
                              />
                              <label htmlFor="for-sp-base-scheme-http">
                                http
                              </label>
                            </>
                          );
                        }}
                      />
                    </div>
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spSignMetadata"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-sign-metadata"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-sign-metadata">
                            Sign metadata using certificates specified below
                          </label>
                        </>
                      )}
                    />
                  </div>
                </div>
              </div>

              {/* Key and Certificates Section */}
              <div className="formrow">
                <span
                  className={`disclosure inline line-height-2 ${this.state.showKeyAndCertificatesState ? 'disclosed' : ''}`}
                  onClick={() => this.showKeyAndCertificates.click.next()}
                >
                  Key and Certificates
                </span>{' '}
                {this.state.showKeyAndCertificatesHasErrors && (
                  <span className="error inline">
                    <span className="icon-info-warning">
                      <span className="icon fa-warning"></span>{' '}
                    </span>
                    Requires attention
                  </span>
                )}
                <div
                  hidden={!this.state.showKeyAndCertificatesState}
                  className="margin-top-half margin-bottom-half indent-1-5 margin-bottom-1"
                >
                  <div className="formrow fix-width-8-1">
                    <label htmlFor="key">Key</label>
                    <p className="desc">
                      This key is used for signing and decryption.
                    </p>
                    <FieldControl
                      strict={false}
                      name="spKey"
                      render={() => (
                        <>
                          <MnFileReader
                            value={get('spKey').value}
                            onChange={(e) => this.setSpKey(e)}
                            disabled={!this.state.enabled}
                          />
                          <p className="desc margin-top-half margin-bottom-0">
                            Supported file types: .pem format
                          </p>
                          <div
                            className="error"
                            hidden={!httpError?.errors?.spKey}
                          >
                            {httpError?.errors?.spKey}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-8-1">
                    <label htmlFor="certificate">Certificate</label>
                    <FieldControl
                      strict={false}
                      name="spCertificate"
                      render={() => (
                        <>
                          <MnFileReader
                            value={get('spCertificate').value}
                            onChange={(e) => this.setSpCertificate(e)}
                            disabled={!this.state.enabled}
                          />
                          <p className="desc margin-top-half margin-bottom-0">
                            Supported file types: .pem format
                          </p>
                          <div
                            className="error"
                            hidden={!httpError?.errors?.spCertificate}
                          >
                            {httpError?.errors?.spCertificate}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-8-1">
                    <label htmlFor="certificate-chain">
                      Certificate chain (optional)
                    </label>
                    <p className="desc">
                      These certificates will be passed to IDP as metadata. IDP
                      will use them for signature validation and encryption
                    </p>
                    <FieldControl
                      strict={false}
                      name="spChain"
                      render={() => (
                        <>
                          <MnFileReader
                            value={get('spChain').value}
                            onChange={(e) => this.setSpChain(e)}
                            disabled={!this.state.enabled}
                          />
                          <p className="desc margin-top-half margin-bottom-0">
                            Supported file types: .pem format
                          </p>
                          <div
                            className="error"
                            hidden={!httpError?.errors?.spChain}
                          >
                            {httpError?.errors?.spChain}
                          </div>
                        </>
                      )}
                    />
                  </div>
                </div>
              </div>

              <div className="formrow margin-top-1-5">
                <h4>Identity Provider Configuration</h4>
              </div>

              {/* Identity Provider Metadata Section */}
              <div className="formrow">
                <span
                  className={`disclosure inline line-height-2 ${this.state.showIdentityProviderMetaDataState ? 'disclosed' : ''}`}
                  onClick={() => this.showIdentityProviderMetaData.click.next()}
                >
                  Metadata
                </span>{' '}
                {this.state.showIdentityProviderMetaDataHasErrors && (
                  <span className="error inline">
                    <span className="icon-info-warning">
                      <span className="icon fa-warning"></span>{' '}
                    </span>
                    Requires attention
                  </span>
                )}
                <div
                  hidden={!this.state.showIdentityProviderMetaDataState}
                  className="margin-top-half margin-bottom-half indent-1-5 margin-bottom-1"
                >
                  <div className="formrow">
                    <label>Load IDP metadata from</label>
                    <div className="formrow checkbox-list">
                      <FieldControl
                        strict={false}
                        name="idpMetadataOrigin"
                        render={({ handler }) => {
                          const field = handler('switch');
                          return (
                            <>
                              <input
                                {...field}
                                type="radio"
                                id="for-idp-metadata-origin-url"
                                value="http"
                                checked={field.value === 'http'}
                              />
                              <label htmlFor="for-idp-metadata-origin-url">
                                URL
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-idp-metadata-origin-file"
                                value="upload"
                                checked={field.value === 'upload'}
                              />
                              <label htmlFor="for-idp-metadata-origin-file">
                                File
                              </label>
                            </>
                          );
                        }}
                      />
                    </div>
                  </div>

                  <div
                    hidden={get('idpMetadataOrigin')?.value !== 'http'}
                    className="formrow fix-width-5"
                  >
                    <FieldControl
                      strict={false}
                      name="idpMetadataURL"
                      render={({ handler }) => {
                        return (
                          <>
                            <label htmlFor="idp-origin-url-field">URL</label>
                            <input
                              type="text"
                              id="idp-origin-url-field"
                              autoCorrect="off"
                              spellCheck="false"
                              autoCapitalize="off"
                              {...handler()}
                            />
                            <div
                              className="error"
                              hidden={!httpError?.errors?.idpMetadataURL}
                            >
                              {httpError?.errors?.idpMetadataURL}
                            </div>
                          </>
                        );
                      }}
                    />
                  </div>

                  <div
                    hidden={get('idpMetadataOrigin')?.value !== 'upload'}
                    className="formrow fix-width-8-1"
                  >
                    <label htmlFor="idp-origin-file-field">File</label>
                    <FieldControl
                      strict={false}
                      name="idpMetadata"
                      render={() => (
                        <>
                          <MnFileReader
                            value={get('idpMetadata').value}
                            onChange={(e) => this.setIdpMetadata(e)}
                            disabled={!this.state.enabled}
                          />
                          <p className="desc margin-top-half margin-bottom-0">
                            Supported file types: .xml
                          </p>
                          <div
                            className="error"
                            hidden={!httpError?.errors?.idpMetadata}
                          >
                            {httpError?.errors?.idpMetadata}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div
                    hidden={get('idpMetadataOrigin')?.value !== 'http'}
                    className="formrow form-inline"
                  >
                    <FieldControl
                      strict={false}
                      name="idpMetadataRefreshIntervalSFlag"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="idpMetadataRefreshIntervalS-flag"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="idpMetadataRefreshIntervalS-flag">
                            Reload IDP metadata every
                          </label>
                        </>
                      )}
                    />
                    <FieldControl
                      strict={false}
                      name="idpMetadataRefreshIntervalS"
                      render={({ handler }) => (
                        <input
                          type="text"
                          className="fix-width-1 margin-right-half"
                          autoCorrect="off"
                          spellCheck="false"
                          autoCapitalize="off"
                          {...handler()}
                        />
                      )}
                    />
                    seconds
                    <div
                      className="error"
                      hidden={!httpError?.errors?.idpMetadataRefreshIntervalS}
                    >
                      {httpError?.errors?.idpMetadataRefreshIntervalS}
                    </div>
                  </div>

                  <div
                    className="formrow"
                    hidden={get('idpMetadataOrigin')?.value === 'upload'}
                  >
                    <FieldControl
                      strict={false}
                      name="idpMetadataTLSVerifyPeer"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="idpMetadataTLSVerifyPeer_flag"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="idpMetadataTLSVerifyPeer_flag">
                            Verify remote peer
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div
                    hidden={
                      !get('idpMetadataTLSVerifyPeer')?.value ||
                      get('idpMetadataOrigin')?.value === 'upload'
                    }
                    className="formrow fix-width-8-1"
                  >
                    <label htmlFor="caCertificates_field">
                      CA Certificates
                    </label>
                    <FieldControl
                      strict={false}
                      name="idpMetadataTLSCAs"
                      render={() => (
                        <>
                          <MnFileReader
                            value={get('idpMetadataTLSCAs').value}
                            onChange={(e) => this.setIdpMetadataTLSCAs(e)}
                            disabled={!this.state.enabled}
                          />
                          <p className="desc margin-top-half margin-bottom-0">
                            Supported file types: .pem format
                          </p>
                          <div
                            className="error"
                            hidden={!httpError?.errors?.idpMetadataTLSCAs}
                          >
                            {httpError?.errors?.idpMetadataTLSCAs}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div
                    className="formrow"
                    hidden={get('idpMetadataOrigin')?.value === 'upload'}
                  >
                    <FieldControl
                      strict={false}
                      name="idpSignsMetadata"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="idp-signs-metadata"
                            value="everything"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="idp-signs-metadata">
                            Validate metadata using trusted fingerprints
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div
                    hidden={
                      !get('idpSignsMetadata')?.value ||
                      get('idpMetadataOrigin')?.value === 'upload'
                    }
                    className="formrow"
                  >
                    <FieldControl
                      strict={false}
                      name="spTrustedFingerprintsUsageMetadata"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="use-trusted-fingerprints-for-bt-only"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="use-trusted-fingerprints-for-bt-only">
                            Use trusted fingerprints for metadata bootstrap only
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spTrustedFingerprintsUsageEverything"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-trusted-fingerprints-usage"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-trusted-fingerprints-usage">
                            Always use trusted fingerprints to validate
                            signatures in SAML requests and responses (ignore
                            certificates received in IDP metadata)
                          </label>
                        </>
                      )}
                    />
                  </div>

                  {this.state.hasRemotePeerWarning && (
                    <span className="error inline">
                      <span className="icon-info-warning">
                        <span className="icon fa-warning"></span>
                      </span>
                      Verify remote peer and validation of trusted fingerprints
                      are both off.
                    </span>
                  )}
                </div>
              </div>
              {/* Trusted Fingerprints Section */}
              <div className="formrow">
                <span
                  className={`disclosure inline line-height-2 ${this.state.showTrustedFingerprintsState ? 'disclosed' : ''}`}
                  onClick={() => this.showTrustedFingerprints.click.next()}
                >
                  Trusted Fingerprints
                </span>{' '}
                {this.state.showTrustedFingerprintsHasErrors && (
                  <span className="error inline">
                    <span className="icon-info-warning">
                      <span className="icon fa-warning"></span>{' '}
                    </span>
                    Requires attention
                  </span>
                )}
                <div
                  hidden={!this.state.showTrustedFingerprintsState}
                  className="margin-top-half margin-bottom-half indent-1-5 margin-bottom-1"
                >
                  <div className="formrow fix-width-5">
                    <label htmlFor="trustedFingerPrints_field">
                      Trusted Fingerprints
                    </label>
                    <FieldControl
                      strict={false}
                      name="spTrustedFingerprints"
                      render={() => (
                        <>
                          <MnFileReader
                            value={get('spTrustedFingerprints').value}
                            onChange={(e) => this.setSpTrustedFingerprints(e)}
                            disabled={!this.state.enabled}
                          />
                          <p className="desc margin-bottom-0">
                            Supported formats:
                          </p>
                          <p className="desc margin-bottom-0 margin-top-0">
                            &#60;type&#62;:&#60;base64&#62;, eg.
                            "sha512:BQwFgN8..."
                          </p>
                          <p className="desc margin-top-0">
                            &#60;hex&#62;, e.g. "01:0a:03:28:0a..."
                          </p>
                          <div
                            className="error"
                            hidden={!httpError?.errors?.spTrustedFingerprints}
                          >
                            {httpError?.errors?.spTrustedFingerprints}
                          </div>
                        </>
                      )}
                    />
                  </div>
                </div>
              </div>

              <div className="formrow margin-top-1-5">
                <h4>Settings</h4>
              </div>

              {/* Single Sign-On Section */}
              <div className="formrow">
                <span
                  className={`disclosure inline line-height-2 ${this.state.showSingleSignOnState ? 'disclosed' : ''}`}
                  onClick={() => this.showSingleSignOn.click.next()}
                >
                  Single Sign-On
                </span>{' '}
                {this.state.showSingleSignOnHasErrors && (
                  <span className="error inline">
                    <span className="icon-info-warning">
                      <span className="icon fa-warning"></span>{' '}
                    </span>
                    Requires attention
                  </span>
                )}
                <div
                  hidden={!this.state.showSingleSignOnState}
                  className="margin-top-half margin-bottom-half indent-1-5 margin-bottom-1"
                >
                  <div className="formrow">
                    <label>Authentication IDP Binding</label>
                    <div className="formrow checkbox-list">
                      <FieldControl
                        strict={false}
                        name="idpAuthnBinding"
                        render={({ handler }) => {
                          const field = handler('switch');
                          return (
                            <>
                              <input
                                {...field}
                                type="radio"
                                id="for-auth-idp-binding-post"
                                value="post"
                                checked={field.value === 'post'}
                              />
                              <label htmlFor="for-auth-idp-binding-post">
                                Post
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-auth-idp-binding-redirect"
                                value="redirect"
                                checked={field.value === 'redirect'}
                              />
                              <label htmlFor="for-auth-idp-binding-redirect">
                                Redirect
                              </label>
                            </>
                          );
                        }}
                      />
                    </div>
                  </div>

                  <div className="formrow">
                    <label>Logout IDP binding</label>
                    <div className="formrow checkbox-list">
                      <FieldControl
                        strict={false}
                        name="idpLogoutBinding"
                        render={({ handler }) => {
                          const field = handler('switch');
                          return (
                            <>
                              <input
                                {...field}
                                type="radio"
                                id="for-logout-idp-binding-post"
                                value="post"
                                checked={field.value === 'post'}
                              />
                              <label htmlFor="for-logout-idp-binding-post">
                                Post
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-logout-idp-binding-redirect"
                                value="redirect"
                                checked={field.value === 'redirect'}
                              />
                              <label htmlFor="for-logout-idp-binding-redirect">
                                Redirect
                              </label>
                            </>
                          );
                        }}
                      />
                    </div>
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spVerifyAssertionSig"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-verify-assertion-sig"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-verify-assertion-sig">
                            Validate assertion signature
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spVerifyAssertionEnvelopSig"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-verify-assertion-envelop-sig"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-verify-assertion-envelop-sig">
                            Validate assertion envelope signature
                          </label>
                        </>
                      )}
                    />
                  </div>

                  {this.state.hasSignatureWarning && (
                    <span className="error inline margin-bottom-1">
                      <span className="icon-info-warning">
                        <span className="icon fa-warning"></span>
                      </span>
                      Both signature validations are off.
                    </span>
                  )}

                  <div className="formrow fix-width-5 margin-bottom-2">
                    <FieldControl
                      strict={false}
                      name="authnNameIDFormat"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="idpUrl_field">NameID format*</label>
                          <input
                            type="text"
                            id="idpUrl_field"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.authnNameIDFormat}
                          >
                            {httpError?.errors?.authnNameIDFormat}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="usernameAttributeFlag"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-username-attribute-flag"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-username-attribute-flag">
                            Username attribute
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-5 margin-bottom-2">
                    <FieldControl
                      strict={false}
                      name="usernameAttribute"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="usernameAttribute">
                            Username attribute
                          </label>
                          <input
                            type="text"
                            id="usernameAttribute"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.usernameAttribute}
                          >
                            {httpError?.errors?.usernameAttribute}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="groupsAttributeFlag"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="groups-attribute-flag"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="groups-attribute-flag">
                            Groups attribute
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-5">
                    <FieldControl
                      strict={false}
                      name="groupsAttribute"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="groups-attribute">
                            Groups attribute
                          </label>
                          <input
                            type="text"
                            id="groups-attribute"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.groupsAttribute}
                          >
                            {httpError?.errors?.groupsAttribute}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-5">
                    <FieldControl
                      strict={false}
                      name="groupsAttributeSep"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="groups-attribute-sep">
                            Groups separator
                          </label>
                          <input
                            type="text"
                            id="groups-attribute-sep"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.groupsAttributeSep}
                          >
                            {httpError?.errors?.groupsAttributeSep}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-5 margin-bottom-2">
                    <FieldControl
                      strict={false}
                      name="groupsFilterRE"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="groups-filter">Groups filter</label>
                          <input
                            type="text"
                            id="groups-filter"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.groupsFilterRE}
                          >
                            {httpError?.errors?.groupsFilterRE}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="rolesAttributeFlag"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="roles-attribute-flag"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="roles-attribute-flag">
                            Roles attribute
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-5">
                    <FieldControl
                      strict={false}
                      name="rolesAttribute"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="roles-attribute">
                            Roles attribute
                          </label>
                          <input
                            type="text"
                            id="roles-attribute"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.rolesAttribute}
                          >
                            {httpError?.errors?.rolesAttribute}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-5">
                    <FieldControl
                      strict={false}
                      name="rolesAttributeSep"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="roles-seperator">
                            Roles separator
                          </label>
                          <input
                            type="text"
                            id="roles-seperator"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.rolesAttributeSep}
                          >
                            {httpError?.errors?.rolesAttributeSep}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow fix-width-5">
                    <FieldControl
                      strict={false}
                      name="rolesFilterRE"
                      render={({ handler }) => (
                        <>
                          <label htmlFor="roles-filter">Roles filter</label>
                          <input
                            type="text"
                            id="roles-filter"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                          <div
                            className="error"
                            hidden={!httpError?.errors?.rolesFilterRE}
                          >
                            {httpError?.errors?.rolesFilterRE}
                          </div>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="singleLogoutEnabled"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-enable-single-logout"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-enable-single-logout">
                            Enable Single Log-Out
                          </label>
                        </>
                      )}
                    />
                  </div>
                </div>
              </div>

              <div className="formrow margin-bottom-5">
                <span
                  className={`disclosure inline line-height-2 ${this.state.showAdvancedState ? 'disclosed' : ''}`}
                  onClick={() => this.showAdvanced.click.next()}
                >
                  Advanced
                </span>{' '}
                {this.state.showAdvancedHasErrors && (
                  <span className="error inline">
                    <span className="icon-info-warning">
                      <span className="icon fa-warning"></span>{' '}
                    </span>
                    Requires attention
                  </span>
                )}
                <div
                  hidden={!this.state.showAdvancedState}
                  className="margin-top-half margin-bottom-half indent-1-5 margin-bottom-1"
                >
                  <div className="formrow form-inline">
                    <div className="row flex-left">
                      Metadata connect timeout
                      <FieldControl
                        strict={false}
                        name="idpMetadataHttpTimeoutMs"
                        render={({ handler }) => (
                          <input
                            type="text"
                            className="fix-width-1 margin-right-half margin-left-half"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                        )}
                      />
                      ms
                    </div>
                  </div>

                  <div
                    className="error"
                    hidden={!httpError?.errors?.idpMetadataHttpTimeoutMs}
                  >
                    {httpError?.errors?.idpMetadataHttpTimeoutMs}
                  </div>

                  <div className="formrow">
                    <label>Metadata connect address family</label>
                    <div className="formrow checkbox-list">
                      <FieldControl
                        strict={false}
                        name="idpMetadataConnectAddressFamily"
                        render={({ handler }) => {
                          const field = handler('switch');
                          return (
                            <>
                              <input
                                {...field}
                                type="radio"
                                id="for-idp-metadata-connect-address-family-auto"
                                value="undefined"
                                checked={field.value === 'undefined'}
                              />
                              <label htmlFor="for-idp-metadata-connect-address-family-auto">
                                Auto
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-idp-metadata-connect-address-family-inet"
                                value="inet"
                                checked={field.value === 'inet'}
                              />
                              <label htmlFor="for-idp-metadata-connect-address-family-inet">
                                Inet
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-idp-metadata-connect-address-family-inet6"
                                value="inet6"
                                checked={field.value === 'inet6'}
                              />
                              <label htmlFor="for-idp-metadata-connect-address-family-inet6">
                                Inet6
                              </label>
                            </>
                          );
                        }}
                      />
                    </div>
                  </div>

                  <div className="formrow form-inline">
                    <div className="row flex-left">
                      Value of SP metadata cacheDuration attribute
                      <FieldControl
                        strict={false}
                        name="spMetadataCacheDuration"
                        render={({ handler }) => (
                          <input
                            type="text"
                            className="fix-width-1 margin-right-half margin-left-half"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...handler()}
                          />
                        )}
                      />
                      (ISO8601 duration)
                    </div>
                    <div
                      className="error"
                      hidden={!httpError?.errors?.spMetadataCacheDuration}
                    >
                      {httpError?.errors?.spMetadataCacheDuration}
                    </div>
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spSignRequests"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-sign-requests"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-sign-requests">
                            Sign authentication requests
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spSessionExpire"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-session-expire"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-session-expire">
                            Respect "SessionNotOnOrAfter" (expire UI session
                            with respect to "SessionNotOnOrAfter" attribute set
                            by IDP)
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spVerifyIssuer"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-verify-issuer"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-verify-issuer">
                            Validate assertion issuer (should match IDP entity
                            id)
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spVerifyRecipientFlag"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-verify-recipient"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-verify-recipient">
                            Validate recipient in SAML response
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div
                    hidden={!get('spVerifyRecipientFlag')?.value}
                    className="formrow fix-width-8-1"
                  >
                    <div className="formrow checkbox-list margin-left-2">
                      <FieldControl
                        strict={false}
                        name="spVerifyRecipient"
                        render={({ handler }) => {
                          const field = handler('switch');
                          return (
                            <>
                              <input
                                {...field}
                                type="radio"
                                id="sp-verify-recipient-acs"
                                value="consumeURL"
                                checked={field.value === 'consumeURL'}
                              />
                              <label htmlFor="sp-verify-recipient-acs">
                                Must be equal to ACS URL
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="sp-verify-recipient-custom"
                                value="custom"
                                checked={field.value === 'custom'}
                              />
                              <label htmlFor="sp-verify-recipient-custom">
                                Must be equal to custom recipient
                              </label>
                            </>
                          );
                        }}
                      />
                    </div>

                    <div
                      hidden={get('spVerifyRecipient')?.value !== 'custom'}
                      className="formrow fix-width-8-1"
                    >
                      <FieldControl
                        strict={false}
                        name="spVerifyRecipientValue"
                        render={({ handler }) => (
                          <>
                            <label htmlFor="customRecipient">
                              Custom Recipient
                            </label>
                            <input
                              type="text"
                              id="customRecipient"
                              autoCorrect="off"
                              spellCheck="false"
                              autoCapitalize="off"
                              {...handler()}
                            />
                            <p className="desc">
                              Custom URL should contain scheme host and
                              optionally port.
                            </p>
                            <div
                              className="error"
                              hidden={
                                !httpError?.errors?.spVerifyRecipientValue
                              }
                            >
                              {httpError?.errors?.spVerifyRecipientValue}
                            </div>
                          </>
                        )}
                      />
                    </div>
                  </div>

                  <div className="formrow checkbox-list">
                    <FieldControl
                      strict={false}
                      name="spVerifyLogoutReqSig"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="for-sp-verify-logout-request"
                            {...handler('checkbox')}
                          />
                          <label htmlFor="for-sp-verify-logout-request">
                            Validate logout request signature
                          </label>
                        </>
                      )}
                    />
                  </div>

                  <div className="formrow">
                    <label>SP Assertion Dupe Check</label>
                    <p>
                      Maintain Global or Local cache of used assertions in order
                      to prevent using the same assertion twice
                    </p>
                    <div className="formrow checkbox-list">
                      <FieldControl
                        strict={false}
                        name="spAssertionDupeCheckFlag"
                        render={({ handler }) => (
                          <>
                            <input
                              type="checkbox"
                              id="for-sp-assertion-dupe-check-flag"
                              {...handler('checkbox')}
                            />
                            <label htmlFor="for-sp-assertion-dupe-check-flag">
                              Enable Dupe Check
                            </label>
                          </>
                        )}
                      />
                    </div>
                    <div
                      hidden={!get('spAssertionDupeCheckFlag')?.value}
                      className="formrow checkbox-list margin-left-2"
                    >
                      <FieldControl
                        strict={false}
                        name="spAssertionDupeCheck"
                        render={({ handler }) => {
                          const field = handler('switch');
                          return (
                            <>
                              <input
                                {...field}
                                type="radio"
                                id="for-sp-assertion-dupe-check-global"
                                value="global"
                                checked={field.value === 'global'}
                              />
                              <label htmlFor="for-sp-assertion-dupe-check-global">
                                Global
                              </label>
                              <input
                                {...field}
                                type="radio"
                                id="for-sp-assertion-dupe-check-local"
                                value="local"
                                checked={field.value === 'local'}
                              />
                              <label htmlFor="for-sp-assertion-dupe-check-local">
                                Local
                              </label>
                            </>
                          );
                        }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Footer */}
              <footer
                className="footer-save"
                hidden={!permissionsAdminSecurityWrite}
              >
                <button
                  disabled={Object.keys(httpError?.errors || {}).length > 0}
                  type="submit"
                  className="margin-right-2"
                >
                  Save
                </button>
                <a className="text-medium" onClick={this.cancel}>
                  Cancel/Reset
                </a>
              </footer>
            </form>
          )}
        />
      </div>
    );
  }
}
