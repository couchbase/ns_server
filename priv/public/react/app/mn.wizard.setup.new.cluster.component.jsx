/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {BehaviorSubject, pipe} from 'rxjs';
import {UISref} from '@uirouter/react';
import {filter, map} from 'rxjs/operators';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnHelperService} from './mn.helper.service.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnFormService} from "./mn.form.service.js";
import {FieldGroup, FieldControl} from 'react-reactive-form';
import { UIRouter } from 'mn.react.router';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnWizardSetupNewClusterComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      postSettingsWebHttpError: null
    }
  }

  componentWillMount() {
    this.focusFieldSubject = new BehaviorSubject(true);
    this.uiRouter = UIRouter;
    this.postSettingsWebHttp = MnWizardService.stream.postSettingsWebHttp;

    this.form = MnFormService.create(this);
    this.form
      .setPackPipe(pipe(
        filter(this.canSubmit.bind(this)),
        map(this.getValues.bind(this))))
      .setFormGroup(MnWizardService.wizardForm.newCluster)
      .setPostRequest(this.postSettingsWebHttp)
      .showGlobalSpinner()
      .success(this.onSuccess.bind(this));

    this.form.group.setValidators([MnHelperService.validateEqual("user.password",
                                                                 "user.passwordVerify",
                                                                 "passwordMismatch")]);

    this.postSettingsWebHttpError = this.postSettingsWebHttp.error;
    MnHelperReactService.async(this, 'postSettingsWebHttpError');
    MnHelperReactService.mnFocus(this);
  }

  getValues() {
    return [this.form.group.value.user, true];
  }

  canSubmit() {
    return !this.form.group.invalid;
  }

  onSuccess() {
    this.uiRouter.stateService.go('app.wizard.termsAndConditions', null, {location: false});
  }

  render() {
    const { postSettingsWebHttpError } = this.state;
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

        <FieldGroup control={this.form.group} render={({ submitted }) => (
          <form 
            onSubmit={(e) => {
              e.preventDefault();
              this.form.submit.next();
              this.form.group.handleSubmit();
            }}
            className="forms"
            noValidate
          >
            <div className="panel-content">
              <div className="error error-form">
                <FieldControl name="clusterName" render={({ touched, errors }) => (
                  <div hidden={!(touched || submitted) || !errors?.required}>
                    Cluster name is required
                  </div>
                )} />

                <FieldControl name="user.username" render={({ touched, errors }) => (
                  <div hidden={!(touched || submitted) || !errors?.required}>
                    Username is required
                  </div>
                )} />

                <FieldControl name="user.password" render={({ touched, errors }) => (
                  <>
                    <div hidden={!(touched || submitted) || !errors?.required}>
                      Password is required
                    </div>
                    <div hidden={!(touched || submitted) || !errors?.minlength}>
                      A password of at least six characters is required
                    </div>
                  </>
                )} />

                <FieldControl name="user.passwordVerify" render={({ touched }) => (
                  <div hidden={!(touched || submitted) || !(this.form.group.errors?.passwordMismatch)}>
                    The password and verify password fields do not match
                  </div>
                )} />
              </div>

              <div className="formrow">
                <label htmlFor="for-cluster-name-field">Cluster Name</label>
                <FieldControl name="clusterName" render={({ handler }) => (
                  <input
                    ref={(input) => { this.input = input; }}
                    type="text"
                    id="for-cluster-name-field"
                    maxLength="256"
                    autoCorrect="off"
                    spellCheck="false"
                    autoCapitalize="off"
                    {...handler()}
                  />
                )} />
              </div>

              <div>
                <div className="formrow">
                  <label htmlFor="secure-username">Create Admin Username</label>
                  <FieldControl name="user.username" render={({ handler }) => (
                    <input
                      type="text"
                      id="secure-username"
                      autoCorrect="off"
                      spellCheck="false"
                      autoCapitalize="off"
                      {...handler()}
                    />
                  )} />
                </div>

                <div className="error error-form" hidden={!postSettingsWebHttpError?.errors?.username}>
                  {postSettingsWebHttpError?.errors?.username}
                </div>

                <div className="formrow row">
                  <div className="column width-6">
                    <label htmlFor="secure-password">Create Password</label>
                    <FieldControl name="user.password" render={({ handler }) => (
                      <input
                        type="password"
                        id="secure-password"
                        autoCorrect="off"
                        spellCheck="false"
                        placeholder="Create a strong password"
                        {...handler()}
                      />
                    )} />
                  </div>
                  <div className="column width-6">
                    <label htmlFor="secure-password-verify">Confirm Password</label>
                    <FieldControl name="user.passwordVerify" render={({ handler }) => (
                      <input
                        type="password"
                        id="secure-password-verify"
                        autoCorrect="off"
                        spellCheck="false"
                        placeholder="Re-enter the password to confirm"
                        {...handler()}
                      />
                    )} />
                  </div>
                </div>

                <div className="error error-form" hidden={!postSettingsWebHttpError?.errors?.password}>
                  {postSettingsWebHttpError?.errors?.password}
                </div>
              </div>
            </div>

            <div className="panel-footer">
              <UISref to="app.wizard.welcome" options={{ location: false }}>
                <a>&lt; Back</a>
              </UISref>
              <button type="submit">Next: Accept Terms</button>
            </div>
          </form>
        )} />
      </div>
    );
  }
}

export {MnWizardSetupNewClusterComponent};
