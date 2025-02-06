import React, { useMemo } from 'react';
import { NEVER } from 'rxjs';
import {
  pluck,
  switchMap,
  distinctUntilChanged,
  shareReplay,
  map,
} from 'rxjs/operators';

import { useObservable } from './hooks/useObservable.js';
import { useLifeCycleHooksToStream } from './hooks/useLifeCycleHooksToStream.js';
import { MnAuthService } from './mn.auth.service.js';
import { MnFormService } from './mn.form.service.js';
import { MnAdminService } from './mn.admin.service.js';
import { UIRouter } from './mn.react.router.js';
import { FieldGroup, FieldControl, Validators } from 'react-reactive-form';

const MnAuthComponent = () => {
  const lifeCircle = useLifeCycleHooksToStream();

  const postUILoginError = useObservable(
    MnAuthService.stream.postUILogin.error,
    null
  );
  const getAuthMethods = useObservable(
    MnAuthService.stream.getAuthMethods,
    null
  );

  const samlsError = useObservable(
    UIRouter.globals.params$.pipe(
      pluck('samlErrorMsgId'),
      distinctUntilChanged(),
      switchMap((id) => (id ? MnAdminService.getSamlError(id) : NEVER)),
      shareReplay({ refCount: true, bufferSize: 1 })
    ),
    null
  );

  const form = useMemo(
    () =>
      MnFormService.create(lifeCircle)
        .setFormGroup({
          user: ['', Validators.required],
          password: ['', Validators.required],
        })
        .setPackPipe(map(() => [form.group.value, false]))
        .setPostRequest(MnAuthService.stream.postUILogin)
        .showGlobalSpinner()
        .error((status) => {
          if (status === 'passwordExpired') {
            const { user, password } = form.group.value;
            UIRouter.stateService.go(
              'app.authChangePassword',
              { auth: btoa(user + ':' + password) },
              { location: false }
            );
          }
        })
        .success(() => {
          // TODO: revise this
          // $rootScope.mnGlobalSpinnerFlag = true;
          // MnPools.clearCache();
          UIRouter.urlRouter.sync();
        }),
    []
  );

  const certAuth = useMemo(
    () =>
      MnFormService.create(lifeCircle)
        .setFormGroup({})
        .setPackPipe(map(() => [null, true]))
        .setPostRequest(MnAuthService.stream.postUILogin)
        .hasNoHandler(),
    []
  );

  return (
    <div className="sign-in-background">
      <div className="row flex-center items-top dialog_main_wrapper">
        <div>
          <div className="panel dialog-small dialog">
            <div className="panel-header">
              <img
                src="/cb_logo_bug_white.svg"
                width="40"
                height="40"
                className="logobug"
                alt="Couchbase Server"
              />
              <h2>Couchbase Server</h2>
            </div>
            <div hidden={getAuthMethods?.clientCertificates === 'must_use'}>
              <FieldGroup
                control={form.group}
                render={({ invalid }) => (
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      form.submit.next();
                    }}
                    novalidate
                    className="forms"
                  >
                    <div className="panel-content">
                      <div
                        className="error error-form"
                        hidden={!postUILoginError}
                      >
                        <span>
                          {postUILoginError === 'initialized'
                            ? 'This cluster has been initialized.'
                            : ''}
                        </span>
                        <span>
                          {postUILoginError === 400
                            ? 'Login failed. Please try again.'
                            : ''}
                        </span>
                        <span>
                          {postUILoginError === 401
                            ? 'Login failed. Please try again.'
                            : ''}
                        </span>
                        <span>
                          {postUILoginError === 403
                            ? 'User does not have permission to log into the UI.'
                            : ''}
                        </span>
                        <span>
                          {postUILoginError === 410
                            ? "The client's version does not match the server's. Please reload the tab."
                            : ''}
                        </span>
                      </div>

                      <FieldControl
                        name="user"
                        render={({ handler, touched, hasError }) => (
                          <div className="formrow">
                            <input
                              autocorrect="off"
                              spellcheck="false"
                              autocapitalize="off"
                              type="text"
                              id="auth-username-input"
                              name="username"
                              placeholder="Username"
                              autoFocus
                              {...handler()}
                            />
                            <div
                              hidden={!touched}
                              className="error error-field"
                            >
                              <div hidden={!hasError('required')}>
                                Username is required.
                              </div>
                            </div>
                          </div>
                        )}
                      />

                      <FieldControl
                        name="password"
                        render={({ handler, touched, hasError }) => (
                          <div className="formrow">
                            <input
                              type="password"
                              autocorrect="off"
                              spellcheck="false"
                              id="auth-password-input"
                              name="password"
                              placeholder="Password"
                              {...handler()}
                            />
                            <div
                              hidden={!touched}
                              className="error error-field"
                            >
                              <div hidden={!hasError('required')}>
                                Password is required.
                              </div>
                            </div>
                          </div>
                        )}
                      />
                    </div>
                    <div className="panel-footer flex-end">
                      <button disabled={invalid} type="submit">
                        Sign In
                      </button>
                    </div>
                  </form>
                )}
              />
            </div>

            <div
              className="forms"
              hidden={
                !getAuthMethods?.saml ||
                getAuthMethods?.clientCertificates === 'must_use'
              }
            >
              <hr />
              <div className="panel-content border-top">
                <div className="error error-form" hidden={!samlsError}>
                  <span>{samlsError?.error}</span>
                </div>
                <div className="row flex-right">
                  <a href="/saml/auth" className="btn outline min-width-full">
                    Sign In Using SSO
                  </a>
                </div>
              </div>
            </div>

            <div
              className="forms"
              hidden={
                getAuthMethods === null ||
                getAuthMethods?.clientCertificates === 'cannot_use'
              }
            >
              <hr />
              <div className="panel-content border-top">
                <div className="row flex-right">
                  <button
                    onClick={() => certAuth.submit.next()}
                    className="outline min-width-full"
                    type="submit"
                  >
                    Sign In With Certificate
                  </button>
                </div>
              </div>
            </div>
          </div>
          <div
            className="supported-browsers"
            title="Chrome 67+, Firefox 67+, Safari 11.1+, Edge 80+"
          >
            Chrome, Firefox, Edge, Safari
          </div>
        </div>
      </div>
    </div>
  );
};

export { MnAuthComponent };
