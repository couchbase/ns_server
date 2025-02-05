import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnLogsCollectInfoService } from './mn.logs.collectInfo.service.js';
import { MnFormService } from './mn.form.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnAdminService } from './mn.admin.service.js';
import { MnSecuritySecretsService } from './mn.security.secrets.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { Subject } from 'rxjs';
import {
  takeUntil,
  map,
  first,
  startWith,
  pairwise,
  switchMap,
  filter,
} from 'rxjs/operators';
import {
  FieldGroup,
  FieldControl,
  FormControl,
  FormBuilder,
  Validators,
} from 'react-reactive-form';
import { MnSpinner } from './components/directives/mn_spinner.jsx';
import { UIRouter } from 'mn.react.router';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import { MnSelectableNodesComponent } from './mn.selectable.nodes.component.jsx';
import { MnLogsCollectInfoStopCollectionComponent } from './mn.logs.collectInfo.stop.collection.component.jsx';
import { ModalContext } from './uib/template/modal/window.and.backdrop.jsx';
import { MnClusterSummaryDialogComponent } from './mn.cluster.summary.dialog.component.jsx';

class MnLogsCollectInfoFormComponent extends MnLifeCycleHooksToStream {
  static contextType = ModalContext;

  constructor(props) {
    super(props);

    this.state = {
      taskCollectInfo: null,
      disableStopCollection: false,
      postRequestError: null,
      isEnterprise: false,
      compatVersion55: false,
      compatVersion80: false,
      isLogEncryptionAtRestEnabled: false,
      viewLoading: true,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    this.postRequest = MnLogsCollectInfoService.stream.startLogsCollection;
    this.formData = MnLogsCollectInfoService.stream.formData;

    this.form = MnFormService.create(this)
      .setSource(this.formData)
      .setFormGroup({
        nodes: FormBuilder.group(
          {},
          { validators: this.nodesCustomValidator.bind(this) }
        ),
        logs: FormBuilder.group({
          logRedactionLevel: null,
          enableTmpDir: null,
          tmpDir: [null, [Validators.required]],
          enableLogDir: null,
          logDir: [null, [Validators.required]],
          enableLogEncryption: null,
          encryptionPassword: [null, [Validators.required]],
          confirmEncryptionPassword: [null, [Validators.required]],
        }),
        upload: FormBuilder.group({
          upload: null,
          uploadHost: [null, [Validators.required]],
          customer: [null, [Validators.required]],
          uploadProxy: null,
          bypassReachabilityChecks: null,
          ticket: null,
        }),
      })
      .setPackPipe(map(this.packData.bind(this)))
      .setPostRequest(this.postRequest)
      .success(() => {
        UIRouter.stateService.go('app.admin.logs.collectInfo.result');
      });

    this.maybeDisableField(
      'logs.encryptionPassword',
      this.form.group.get('logs.enableLogEncryption').value
    );
    this.maybeDisableField(
      'logs.confirmEncryptionPassword',
      this.form.group.get('logs.enableLogEncryption').value
    );

    this.isEnterprise = MnPoolsService.stream.isEnterprise;
    MnHelperReactService.async(this, 'isEnterprise');

    this.compatVersion55 = MnAdminService.stream.compatVersion55;
    MnHelperReactService.async(this, 'compatVersion55');

    this.compatVersion80 = MnAdminService.stream.compatVersion80;
    MnHelperReactService.async(this, 'compatVersion80');

    this.clickGetClusterInfo = new Subject();
    this.clickGetClusterInfo
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.showClusterInfoDialog.bind(this));

    MnHelperReactService.valueChanges(
      this,
      this.form.group.get('logs.enableTmpDir').valueChanges
    )
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableField.bind(this, 'logs.tmpDir'));

    MnHelperReactService.valueChanges(
      this,
      this.form.group.get('logs.enableLogDir').valueChanges
    )
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableField.bind(this, 'logs.logDir'));

    MnHelperReactService.valueChanges(
      this,
      this.form.group.get('logs.enableLogEncryption').valueChanges
    )
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((enable) => {
        this.maybeDisableField('logs.encryptionPassword', enable);
        this.maybeDisableField('logs.confirmEncryptionPassword', enable);
        if (enable) {
          this.form.group
            .get('logs')
            .setValidators([
              MnHelperService.validateEqual(
                'encryptionPassword',
                'confirmEncryptionPassword',
                'passwordMismatch'
              ),
            ]);
        } else {
          this.form.group.get('logs').clearValidators();
        }
      });

    MnHelperReactService.valueChanges(
      this,
      this.form.group.get('upload.upload').valueChanges
    )
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableField.bind(this, 'upload.customer'));

    MnHelperReactService.valueChanges(
      this,
      this.form.group.get('upload.upload').valueChanges
    )
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableField.bind(this, 'upload.uploadHost'));

    // Subscribe to task status
    this.taskCollectInfo = MnLogsCollectInfoService.stream.taskCollectInfo;
    MnHelperReactService.async(this, 'taskCollectInfo');

    this.disableStopCollection =
      MnLogsCollectInfoService.stream.postCancelLogsCollection.success.pipe(
        switchMap(() => this.taskCollectInfo),
        filter((taskCollectInfo) => taskCollectInfo.status === 'running')
      );
    MnHelperReactService.async(this, 'disableStopCollection');

    // Subscribe to enterprise status
    this.isEnterprise = MnLogsCollectInfoService.stream.isEnterprise;
    MnHelperReactService.async(this, 'isEnterprise');

    // Subscribe to encryption status
    this.isLogEncryptionAtRestEnabled =
      MnSecuritySecretsService.stream.getEncryptionAtRest.pipe(
        first(),
        map(
          (encryption) =>
            encryption.log.encryptionMethod !== 'disabled' ||
            encryption.config.encryptionMethod !== 'disabled'
        )
      );
    MnHelperReactService.async(this, 'isLogEncryptionAtRestEnabled');

    this.isLogEncryptionAtRestEnabled
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((isLogEncryptionAtRestEnabled) => {
        return this.form.group
          .get('logs.enableLogEncryption')
          .patchValue(isLogEncryptionAtRestEnabled);
      });

    // Subscribe to post request errors
    this.postRequestError =
      MnLogsCollectInfoService.stream.startLogsCollection.error;
    MnHelperReactService.async(this, 'postRequestError');

    // Initialize form data
    MnLogsCollectInfoService.stream.formData
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => this.setState({ viewLoading: false }));

    this.nodesByOtp = MnAdminService.stream.nodesByOtp;
    this.nodesByOtp
      .pipe(startWith([{}, {}]), pairwise(), takeUntil(this.mnOnDestroy))
      .subscribe(this.addNodes.bind(this));
    MnHelperReactService.async(this, 'nodesByOtp');
  }

  showClusterInfoDialog() {
    const { openModal } = this.context;
    openModal({
      component: MnClusterSummaryDialogComponent,
    });
  }

  packData() {
    let packedData = {};

    let nodes = this.form.group.controls.nodes.getRawValue();
    let logs = this.form.group.controls.logs.getRawValue();
    let upload = this.form.group.controls.upload.getRawValue();

    packedData.nodes = Object.keys(nodes)
      .filter((node) => nodes[node])
      .join(',');

    if (logs.logRedactionLevel) {
      packedData.logRedactionLevel = logs.logRedactionLevel;
    }

    if (logs.enableTmpDir) {
      packedData.tmpDir = logs.tmpDir;
    }
    if (logs.enableLogDir) {
      packedData.logDir = logs.logDir;
    }
    if (logs.enableLogEncryption) {
      packedData.encryptionPassword = logs.encryptionPassword;
    }

    if (upload.upload) {
      packedData.uploadHost = upload.uploadHost;
      packedData.customer = upload.customer;
      packedData.ticket = upload.ticket || '';
      if (upload.bypassReachabilityChecks) {
        packedData.bypassReachabilityChecks = upload.bypassReachabilityChecks;
      }
      if (upload.uploadProxy) {
        packedData.uploadProxy = upload.uploadProxy;
      }
    }

    return packedData;
  }

  stopCollection() {
    const { openModal } = this.context;
    openModal({
      component: MnLogsCollectInfoStopCollectionComponent,
    });
  }

  addNodes([nodesByOtpOld, nodesByOtpNew]) {
    Object.keys(nodesByOtpNew).forEach((nodeOtp) => {
      let control =
        this.form.group.get('nodes').controls[nodeOtp] || new FormControl();
      control[
        nodesByOtpNew[nodeOtp][0].status === 'unhealthy' ? 'disable' : 'enable'
      ]();

      if (nodesByOtpOld[nodeOtp]) {
        /* at the end of forEach nodesByOtpOld will contain the nodes that were removed (nodesByOtpOld - nodesByOtpNew)
           so we delete from nodesByOtpOld the nodes which are both in nodesByOtpOld and nodesByOtpNew */
        delete nodesByOtpOld[nodeOtp];
      } else {
        // new node added (in nodesByOtpNew, but not in nodesByOtpOld)
        this.form.group.get('nodes').addControl(nodeOtp, control);
      }
    });

    // look for removed nodes
    Object.keys(nodesByOtpOld).forEach((nodeOtp) => {
      this.form.group.get('nodes').removeControl(nodeOtp);
    });
  }

  nodesCustomValidator(formGroup) {
    let nodes = formGroup.getRawValue();
    let invalid = !Object.values(nodes).some((v) => v);
    return invalid ? { nodes: true } : null;
  }

  isFieldValid(formGroup, toggleField, field) {
    let groupValue = formGroup.getRawValue();
    return !(groupValue[toggleField] && !groupValue[field]);
  }

  maybeDisableField(field, enable) {
    this.form.group.get(field)[enable ? 'enable' : 'disable']();
  }

  render() {
    const {
      viewLoading,
      taskCollectInfo,
      disableStopCollection,
      postRequestError,
      isEnterprise,
      compatVersion55,
      compatVersion80,
      isLogEncryptionAtRestEnabled,
    } = this.state;

    if (!this.form) {
      return <MnSpinner mnSpinnerValue={true} />;
    }

    return (
      <div>
        <MnSpinner mnSpinnerValue={viewLoading} />

        <div className="relative">
          <div
            className="row flex-right"
            style={{
              minHeight: 0,
              position: 'absolute',
              top: 0,
              right: 0,
              zIndex: 1,
            }}
          >
            <span>
              {taskCollectInfo?.status === 'running' && (
                <button
                  onClick={this.stopCollection.bind(this)}
                  disabled={disableStopCollection}
                  className="outline"
                >
                  Stop Collection
                </button>
              )}
              {taskCollectInfo?.status !== 'idle' && (
                <button
                  onClick={() =>
                    UIRouter.stateService.go(
                      'app.admin.logs.collectInfo.result'
                    )
                  }
                  className="outline"
                >
                  Show Current Collection
                </button>
              )}
            </span>
          </div>
        </div>

        <div className="max-width-11 margin-top-half padding-bottom-6 padding-left-1">
          {postRequestError?._ && (
            <div className="error error-field">{postRequestError._}</div>
          )}

          <h4 className="margin-bottom-1">
            Collect Logs & Diagnostic Information
          </h4>

          <FieldGroup
            strict={false}
            control={this.form.group}
            render={({ invalid }) => (
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  this.form.submit.next();
                  this.form.group.handleSubmit();
                }}
                className="forms"
              >
                {postRequestError?.nodes && (
                  <div className="error error-field">
                    {postRequestError.nodes}
                  </div>
                )}

                <div className="formrow">
                  <MnSelectableNodesComponent
                    mnSelectAll={true}
                    mnGroup={this.form.group.controls.nodes}
                  />
                </div>

                <FieldControl
                  strict={false}
                  name="logs.logRedactionLevel"
                  render={({ handler }) => {
                    const { value, ...handlerSwitch } = handler('switch');
                    return (
                      isEnterprise &&
                      compatVersion55 && (
                        <div className="formrow">
                          <label>Redact Logs</label>
                          <input
                            checked={value == 'none'}
                            type="radio"
                            value="none"
                            id="redaction_none"
                            name="logs.logRedactionLevel"
                            {...handlerSwitch}
                          />
                          <label htmlFor="redaction_none" className="checkbox">
                            No Redaction
                          </label>

                          <input
                            checked={value == 'partial'}
                            type="radio"
                            value="partial"
                            id="redaction_partial"
                            name="logs.logRedactionLevel"
                            {...handlerSwitch}
                          />
                          <label
                            htmlFor="redaction_partial"
                            className="checkbox margin-right-zero"
                          >
                            Partial Redaction
                          </label>
                          <OverlayTrigger
                            placement="right"
                            trigger="click"
                            rootClose={true}
                            overlay={
                              <Tooltip>
                                In the log file created through this process,
                                user data such as key/value pairs and usernames
                                will be redacted. Metadata and system data will
                                not be redacted. The default redaction
                                configuration in Settings remains unchanged by
                                your choice here.
                              </Tooltip>
                            }
                          >
                            <span className="fa-stack icon-info margin-left-quarter">
                              <span className="icon fa-circle-thin fa-stack-2x"></span>
                              <span className="icon fa-info fa-stack-1x"></span>
                            </span>
                          </OverlayTrigger>
                          {handler().value === 'partial' && (
                            <div className="content-box">
                              <p>
                                Couchbase Server will collect and save a
                                redacted log file at the location you specify,
                                but also save an unredacted version which could
                                be useful for further troubleshooting.
                              </p>
                              <p>
                                If you use the "Upload to Couchbase" feature
                                below, ONLY the redacted log will be uploaded.
                              </p>
                            </div>
                          )}
                        </div>
                      )
                    );
                  }}
                />

                <FieldControl
                  strict={false}
                  name="logs.enableTmpDir"
                  render={({ handler }) => (
                    <div className="formrow fix-width-5">
                      <input
                        type="checkbox"
                        id="for_custom_tmpdir"
                        {...handler('checkbox')}
                      />
                      <label
                        htmlFor="for_custom_tmpdir"
                        className="margin-right-zero"
                      >
                        Specify custom temp directory
                      </label>
                      <OverlayTrigger
                        placement="right"
                        trigger="click"
                        rootClose={true}
                        overlay={
                          <Tooltip>
                            Logs and diagnostics will be combined in this
                            directory during the collection process. The process
                            takes a significant amount of time and the
                            subsequent file tends to be large, so a temporary
                            directory can be a good idea in some production
                            environments.
                          </Tooltip>
                        }
                      >
                        <span className="fa-stack icon-info margin-left-quarter">
                          <span className="icon fa-circle-thin fa-stack-2x"></span>
                          <span className="icon fa-info fa-stack-1x"></span>
                        </span>
                      </OverlayTrigger>

                      {handler('checkbox').value && (
                        <div>
                          <input
                            type="text"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...this.form.group.get('logs.tmpDir').handler()}
                          />
                          {postRequestError?.tmpDir && (
                            <div className="error error-field">
                              {postRequestError.tmpDir}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                />

                <FieldControl
                  strict={false}
                  name="logs.enableLogDir"
                  render={({ handler }) => (
                    <div className="formrow fix-width-5">
                      <input
                        type="checkbox"
                        id="for_custom_logdir"
                        {...handler('checkbox')}
                      />
                      <label
                        htmlFor="for_custom_logdir"
                        className="margin-right-zero"
                      >
                        Specify custom destination directory
                      </label>

                      {handler('checkbox').value && (
                        <div>
                          <input
                            type="text"
                            autoCorrect="off"
                            spellCheck="false"
                            autoCapitalize="off"
                            {...this.form.group.get('logs.logDir').handler()}
                          />
                          {postRequestError?.logDir && (
                            <div className="error error-field">
                              {postRequestError.logDir}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                />

                <div formGroupName="upload">
                  <FieldControl
                    strict={false}
                    name="upload.upload"
                    render={({ handler }) => (
                      <div className="formrow fix-width-5">
                        <input
                          type="checkbox"
                          id="for_upload"
                          {...handler('checkbox')}
                        />
                        <label
                          htmlFor="for_upload"
                          className="margin-right-zero"
                        >
                          Upload to Couchbase
                        </label>

                        {handler('checkbox').value && (
                          <>
                            <div className="formrow fix-width-5">
                              <label>Upload to Host</label>
                              <input
                                type="text"
                                autoCorrect="off"
                                spellCheck="false"
                                autoCapitalize="off"
                                {...this.form.group
                                  .get('upload.uploadHost')
                                  .handler()}
                              />
                              {postRequestError?.uploadHost && (
                                <div className="error error-field">
                                  {postRequestError.uploadHost}
                                </div>
                              )}
                              {this.form.group.get('upload.uploadHost')?.errors
                                ?.required && (
                                <div className="error error-field">
                                  upload host field must be given if upload is
                                  selected
                                </div>
                              )}
                            </div>

                            <div className="formrow fix-width-5">
                              <label>Customer Name</label>
                              <input
                                type="text"
                                autoCorrect="off"
                                spellCheck="false"
                                autoCapitalize="off"
                                {...this.form.group
                                  .get('upload.customer')
                                  .handler()}
                              />
                              {postRequestError?.customer && (
                                <div className="error error-field">
                                  {postRequestError.customer}
                                </div>
                              )}
                              {this.form.group.get('upload.customer')?.errors
                                ?.required && (
                                <div className="error error-field">
                                  A customer name must be given if upload is
                                  selected
                                </div>
                              )}
                            </div>

                            <div className="formrow fix-width-5">
                              <label>
                                Upload Proxy <small>optional</small>
                              </label>
                              <input
                                type="text"
                                autoCorrect="off"
                                spellCheck="false"
                                autoCapitalize="off"
                                {...this.form.group
                                  .get('upload.uploadProxy')
                                  .handler()}
                              />
                              {postRequestError?.upload_proxy && (
                                <div className="error error-field">
                                  {postRequestError.upload_proxy}
                                </div>
                              )}
                              <input
                                type="checkbox"
                                id="bypass_reachability_checks"
                                {...this.form.group
                                  .get('upload.bypassReachabilityChecks')
                                  .handler()}
                              />
                              <label
                                htmlFor="bypass_reachability_checks"
                                className="margin-right-zero"
                              >
                                Bypass Reachability Checks
                              </label>
                              {postRequestError?.bypassReachabilityChecks && (
                                <div className="error error-field">
                                  {postRequestError.bypassReachabilityChecks}
                                </div>
                              )}
                            </div>

                            <div className="formrow fix-width-5">
                              <label>
                                Ticket Number <small>optional</small>
                              </label>
                              <input
                                type="text"
                                id="ticket_input"
                                autoCorrect="off"
                                spellCheck="false"
                                autoCapitalize="off"
                                {...this.form.group
                                  .get('upload.ticket')
                                  .handler()}
                              />
                              {postRequestError?.ticket && (
                                <div className="error error-field">
                                  {postRequestError.ticket}
                                </div>
                              )}
                            </div>
                          </>
                        )}
                      </div>
                    )}
                  />
                </div>

                {compatVersion80 && isEnterprise && (
                  <div className="formrow fix-width-5" formGroupName="logs">
                    <FieldControl
                      strict={false}
                      name="logs.enableLogEncryption"
                      render={({ handler }) => (
                        <>
                          <input
                            type="checkbox"
                            id="enableLogEncryption"
                            {...handler('checkbox')}
                          />
                          <label
                            htmlFor="enableLogEncryption"
                            className="margin-right-zero"
                          >
                            Encrypt collected information by AES
                          </label>
                          <p className="text-smaller margin-left-1-2-5">
                            (only unredacted zip will be encrypted)
                          </p>
                          {!handler().value && isLogEncryptionAtRestEnabled && (
                            <span className="warning text-smaller block margin-left-1-2-5">
                              Warning: Generated logs are not encrypted yet,
                              even though encryption at rest is enabled for
                              configuration or logs.
                              <br />
                              Check this option and set a password to encrypt
                              the logs.
                            </span>
                          )}

                          {handler('checkbox').value && (
                            <>
                              <div className="formrow fix-width-5">
                                <label>Encryption Password</label>
                                <input
                                  type="password"
                                  autoComplete="new-password"
                                  autoCorrect="off"
                                  spellCheck="false"
                                  autoCapitalize="off"
                                  {...this.form.group
                                    .get('logs.encryptionPassword')
                                    .handler()}
                                />
                                {postRequestError?.encryptionPassword && (
                                  <div className="error error-field">
                                    {postRequestError.encryptionPassword}
                                  </div>
                                )}
                                {this.form.group.get('logs')?.errors
                                  ?.encryptionPassword && (
                                  <div className="error error-field">
                                    {
                                      this.form.group.get('logs').errors
                                        .encryptionPassword
                                    }
                                  </div>
                                )}
                              </div>

                              <div className="formrow fix-width-5">
                                <label>Confirm Encryption Password</label>
                                <input
                                  type="password"
                                  autoCorrect="off"
                                  spellCheck="false"
                                  autoCapitalize="off"
                                  {...this.form.group
                                    .get('logs.confirmEncryptionPassword')
                                    .handler()}
                                />
                                {this.form.group.get('logs')?.errors
                                  ?.passwordMismatch && (
                                  <div className="error error-field">
                                    Passwords must match
                                  </div>
                                )}
                              </div>
                            </>
                          )}
                        </>
                      )}
                    />
                  </div>
                )}

                <footer className="footer-save">
                  <button
                    disabled={invalid}
                    type="submit"
                    className="margin-right-2"
                  >
                    Start Collecting
                  </button>
                  <a
                    className="text-medium"
                    onClick={() => this.clickGetClusterInfo.next()}
                  >
                    Get Cluster Summary
                  </a>
                </footer>
              </form>
            )}
          />
        </div>
      </div>
    );
  }
}

export { MnLogsCollectInfoFormComponent };
