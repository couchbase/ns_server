import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import {
  map,
  withLatestFrom,
  pluck,
  switchMap,
  distinctUntilChanged,
  shareReplay,
  takeUntil,
} from 'rxjs/operators';
import { merge, combineLatest, pipe, of } from 'rxjs';
import { FieldGroup, FieldControl } from 'react-reactive-form';
import { MnFormService } from './mn.form.service.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnSecurityService } from './mn.security.service.js';
import MnPermissions from './components/mn_permissions.js';
import { MnAdminService } from './mn.admin.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { MnSpinner } from './components/directives/mn_spinner.jsx';
import { MnSelect } from './components/directives/mn_select/mn_select.jsx';
import { MnSecurityAuditItemComponent } from './mn.security.audit.item.component.jsx';
import { MnSecurityAuditUserActivityRoleComponent } from './mn.security.audit.user.activity.role.component.jsx';
import { MnSecurityAuditUserActivityGroupsComponent } from './mn.security.audit.user.activity.groups.component.jsx';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';

export class MnSecurityAuditComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.IEC = MnHelperService.IEC;

    this.state = {
      descriptorsByModule: null,
      maybeItIsPlural: null,
      httpErrorAudit: null,
      httpErrorUserActivity: null,
      securityWrite: null,
      compatVersion55: null,
      compatVersion80: null,
      isEnterprise: null,
      userActivityUIRoles: {},
      userActivityUIGroups: {},
      userActivitySelectedTab: 'roles',
    };
  }

  componentDidMount() {
    super.componentDidMount();

    this.compatVersion55 = MnAdminService.stream.compatVersion55;
    this.compatVersion80 = MnAdminService.stream.compatVersion80;
    this.isEnterprise = MnPoolsService.stream.isEnterprise;

    MnHelperReactService.async(this, 'compatVersion55');
    MnHelperReactService.async(this, 'compatVersion80');
    MnHelperReactService.async(this, 'isEnterprise');

    this.getAuditDescriptors = MnSecurityService.stream.getAuditDescriptors;
    this.getAudit = MnSecurityService.stream.getAudit;
    this.getUIUserRoles = MnSecurityService.stream.getUIUserRoles;
    this.getUIUserGroups = MnSecurityService.stream.getUIUserGroups;
    this.postAudit = MnSecurityService.stream.postAudit;
    this.postAuditValidation = MnSecurityService.stream.postAuditValidation;
    this.getUserActivity = MnSecurityService.stream.getUserActivity;
    this.postUserActivity = MnSecurityService.stream.postUserActivity;
    this.postUserActivityValidation =
      MnSecurityService.stream.postUserActivityValidation;

    this.securityWrite = MnPermissions.stream.pipe(
      map((permissions) => permissions.cluster.admin.security.write)
    );
    MnHelperReactService.async(this, 'securityWrite');

    this.getAuditInfo = combineLatest(
      this.compatVersion80,
      this.isEnterprise
    ).pipe(
      switchMap(([compat80, isEnterprise]) =>
        compat80 && isEnterprise
          ? combineLatest(
              this.getAudit,
              this.getUserActivity,
              this.getUIUserRoles,
              this.getUIUserGroups
            )
          : this.getAudit
      ),
      shareReplay({ refCount: true, bufferSize: 1 })
    );

    this.form = MnFormService.create(this);

    this.form
      .setFormGroup({
        auditEvents: this.form.builder.group({
          auditdEnabled: null,
          logPath: null,
          rotateInterval: null,
          rotateSize: null,
          rotateUnit: null,
          descriptors: this.form.builder.group({}),
          disabledUsers: null,
        }),
        userActivity: this.form.builder.group({
          enabled: false,
          roleDescriptors: this.form.builder.group({}),
          groupDescriptors: this.form.builder.group({}),
        }),
      })
      .setUnpackPipe(pipe(map(this.unpackInfo.bind(this))))
      .setPackPipe(
        pipe(
          withLatestFrom(this.compatVersion55, this.isEnterprise),
          map(this.prepareAuditDataForSending.bind(this))
        )
      )
      .setSource(this.getAuditInfo)
      .setPostRequest(this.postAudit)
      .setValidation(this.postAuditValidation, this.securityWrite)
      .setPackPipe(
        pipe(
          withLatestFrom(this.compatVersion55, this.isEnterprise),
          map(this.prepareUserActivityDataForSending.bind(this))
        )
      )
      .setPostRequest(this.postUserActivity)
      .setValidation(this.postUserActivityValidation, this.securityWrite)
      .clearErrors()
      .showGlobalSpinner()
      .successMessage('Settings saved successfully!');

    this.httpErrorAudit = merge(
      this.postAudit.error,
      this.postAuditValidation.error
    );
    MnHelperReactService.async(this, 'httpErrorAudit');

    this.httpErrorUserActivity = merge(
      this.postUserActivity.error,
      this.postUserActivityValidation.error
    );
    MnHelperReactService.async(this, 'httpErrorUserActivity');

    this.maybeItIsPlural = MnHelperReactService.valueChanges(
      this,
      this.form.group.get('auditEvents.rotateInterval').valueChanges
    ).pipe(
      distinctUntilChanged(),
      map(this.getEnding.bind(this)),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
    MnHelperReactService.async(this, 'maybeItIsPlural');

    combineLatest(
      MnHelperReactService.valueChanges(
        this,
        this.form.group.get('auditEvents').valueChanges
      ).pipe(pluck('auditdEnabled'), distinctUntilChanged()),
      this.securityWrite
    )
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableAuditFields.bind(this));

    this.securityWrite
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableToggles.bind(this));

    var disabledByID = this.getAudit.pipe(
      pluck('disabled'),
      map(this.getDisabledByID.bind(this))
    );

    this.descriptorsByModule = combineLatest(
      this.getAuditDescriptors,
      disabledByID,
      MnAdminService.stream.compatVersion65.pipe(
        switchMap((is65) =>
          is65
            ? MnSecurityService.stream.getAuditNonFilterableDescriptors
            : of(null)
        )
      )
    ).pipe(
      map(this.getDescriptorsByModule.bind(this)),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
    MnHelperReactService.async(this, 'descriptorsByModule');

    this.userActivityUIRoles = combineLatest(
      this.getUIUserRoles,
      this.getUserActivity
    ).pipe(
      map(this.getUIUserRolesMap.bind(this)),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
    MnHelperReactService.async(this, 'userActivityUIRoles');

    this.userActivityUIGroups = combineLatest(
      this.getUIUserGroups,
      this.getUserActivity
    ).pipe(
      map(this.getUIUserGroupsMap.bind(this)),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
  }

  render() {
    const { form } = this;
    const {
      descriptorsByModule,
      maybeItIsPlural,
      httpErrorAudit,
      httpErrorUserActivity,
      securityWrite,
      compatVersion55,
      compatVersion80,
      isEnterprise,
      userActivityUIRoles,
      userActivitySelectedTab,
    } = this.state;

    const ignoreEventsTooltip = (
      <Tooltip>
        NOTE: Important events (shown in the checked-disabled state above) will
        ALWAYS be logged. Even from these users.
      </Tooltip>
    );

    if (!descriptorsByModule) {
      return <MnSpinner mnSpinner={true} />;
    }

    return (
      <>
        <FieldGroup
          strict={false}
          control={form.group}
          render={({ get }) => (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                form.submit.next();
              }}
              className="forms"
            >
              <div className="row flex-left items-stretch resp-flex-column-med margin-bottom-2">
                <div className="width-6 margin-bottom-5">
                  <div className="formrow">
                    <div className="row flex-left margin-bottom-half">
                      <label
                        className="toggle-control margin-0"
                        htmlFor="audit-enable-flag"
                      >
                        <FieldControl
                          strict={false}
                          name="auditEvents.auditdEnabled"
                          render={({ handler }) => (
                            <input
                              type="checkbox"
                              id="audit-enable-flag"
                              {...handler('checkbox')}
                            />
                          )}
                        />
                        <span className="toggle-control-body"></span>
                      </label>
                      <span className="text-small">
                        &nbsp; Audit events & write them to a log
                      </span>
                    </div>
                    <div
                      hidden={!get('auditEvents.auditdEnabled').value}
                      className="content-box fix-width-6"
                    >
                      Auditing will log a minimum set of events by default.
                      Expand the events modules below to see these defaults
                      and/or select your own set of events. <br />
                      NOTE: The number of events selected for logging may impact
                      your cluster's performance. Audit logs may also use
                      significant disk space.
                    </div>
                  </div>

                  <div className="formrow fix-width-6">
                    <label htmlFor="target-log-field">
                      Audit Log Directory
                    </label>
                    <FieldControl
                      strict={false}
                      name="auditEvents.logPath"
                      render={({ handler }) => (
                        <input
                          type="text"
                          autoCorrect="off"
                          spellCheck="false"
                          autoCapitalize="off"
                          id="target-log-field"
                          {...handler()}
                        />
                      )}
                    />
                    <div
                      className="error error-field"
                      hidden={!httpErrorAudit?.errors?.logPath}
                    >
                      {httpErrorAudit?.errors?.logPath}
                    </div>
                  </div>

                  <label>
                    File Reset Interval{' '}
                    <small>start new empty log after time or size is met</small>
                  </label>
                  <div className="row flex-left fix-width-6">
                    <div className="column form-inline">
                      <FieldControl
                        strict={false}
                        name="auditEvents.rotateInterval"
                        render={({ handler }) => (
                          <input
                            id="log-rotation-interval"
                            className="input-short-1"
                            type="number"
                            {...handler()}
                          />
                        )}
                      />{' '}
                      <FieldControl
                        strict={false}
                        name="auditEvents.rotateUnit"
                        render={({ handler }) => {
                          const field = handler();
                          return (
                            <MnSelect
                              mnDisabled={field.disabled}
                              className="inline align-top"
                              onSelect={({ selectedOption }) => {
                                field.onChange(selectedOption);
                              }}
                              values={['minutes', 'hours', 'days']}
                              labels={['minute', 'hour', 'day'].map((l) =>
                                l.concat(maybeItIsPlural)
                              )}
                              {...field}
                            />
                          );
                        }}
                      />
                    </div>
                    <div className="column">
                      <span className="form-inline">
                        <FieldControl
                          strict={false}
                          name="auditEvents.rotateSize"
                          render={({ handler }) => (
                            <input
                              id="log-rotation-size"
                              type="number"
                              className="input-short-1"
                              {...handler()}
                            />
                          )}
                        />
                        <small> MiB</small>
                      </span>
                    </div>
                  </div>
                  <div className="margin-bottom-1-5">
                    <div
                      className="error error-field"
                      hidden={!httpErrorAudit?.errors?.rotateInterval}
                    >
                      {httpErrorAudit?.errors?.rotateInterval}
                    </div>
                    <div
                      className="error error-field"
                      hidden={!httpErrorAudit?.errors?.rotateSize}
                    >
                      {httpErrorAudit?.errors?.rotateSize}
                    </div>
                  </div>

                  <h4>Events</h4>
                  {isEnterprise && compatVersion55 && (
                    <>
                      {Object.keys(descriptorsByModule || {}).map(
                        (moduleName) => (
                          <MnSecurityAuditItemComponent
                            key={moduleName}
                            group={form.group.get('auditEvents')}
                            descriptors={descriptorsByModule}
                            moduleName={moduleName}
                          />
                        )
                      )}
                      <div className="formrow fix-width-6 margin-top-1 margin-bottom-2">
                        <label className="inline">
                          Ignore Events From These Users&nbsp;
                        </label>
                        <OverlayTrigger
                          placement="right"
                          rootClose={true}
                          trigger="click"
                          overlay={ignoreEventsTooltip}
                        >
                          <span className="icon-info-warning raised">
                            <span className="icon fa-warning"></span>
                          </span>
                        </OverlayTrigger>
                        <FieldControl
                          strict={false}
                          name="auditEvents.disabledUsers"
                          render={({ handler }) => {
                            return (
                              <textarea
                                {...handler()}
                                autoCorrect="off"
                                spellCheck="false"
                                autoCapitalize="off"
                                rows="3"
                                placeholder="e.g. username/external,username/couchbase ..."
                              />
                            );
                          }}
                        />
                        <div
                          className="error error-field"
                          hidden={!httpErrorAudit?.errors?.disabledUsers}
                        >
                          {httpErrorAudit?.errors?.disabledUsers}
                        </div>
                      </div>
                    </>
                  )}
                </div>
                <div className="vertical-page-splitter resp-hide-med">
                  &nbsp;
                </div>
                {isEnterprise && compatVersion80 && (
                  <div className="width-6 margin-bottom-5">
                    <div className="formrow">
                      <div className="row flex-left margin-bottom-half">
                        <label
                          className="toggle-control margin-0"
                          htmlFor="user-activity-enable-flag"
                        >
                          <FieldControl
                            strict={false}
                            name="userActivity.enabled"
                            render={({ handler }) => (
                              <input
                                type="checkbox"
                                id="user-activity-enable-flag"
                                {...handler('checkbox')}
                              />
                            )}
                          />
                          <span className="toggle-control-body"></span>
                        </label>
                        <span className="text-small">&nbsp; User activity</span>
                      </div>
                      <div
                        className="error error-field"
                        hidden={!httpErrorUserActivity?.errors?.enabled}
                      >
                        {httpErrorUserActivity?.errors?.enabled}
                      </div>
                    </div>
                    <div className="formrow margin-top-2">
                      <span className="pills">
                        <a
                          onClick={() =>
                            this.setState({
                              userActivitySelectedTab: 'roles',
                            })
                          }
                          className={
                            userActivitySelectedTab === 'roles'
                              ? 'selected'
                              : ''
                          }
                        >
                          Roles
                        </a>
                        <a
                          onClick={() =>
                            this.setState({
                              userActivitySelectedTab: 'groups',
                            })
                          }
                          className={
                            userActivitySelectedTab === 'groups'
                              ? 'selected'
                              : ''
                          }
                        >
                          Groups
                        </a>
                      </span>
                    </div>
                    <div hidden={userActivitySelectedTab === 'groups'}>
                      {Object.keys(userActivityUIRoles || {}).map((name) => (
                        <section key={name} className="audit-module">
                          <MnSecurityAuditUserActivityRoleComponent
                            group={form.group.get('userActivity')}
                            roleDescriptors={this.userActivityUIRoles}
                            moduleName={name}
                          />
                        </section>
                      ))}
                    </div>
                    <div hidden={userActivitySelectedTab === 'roles'}>
                      <section className="audit-module">
                        <MnSecurityAuditUserActivityGroupsComponent
                          group={form.group.get('userActivity')}
                          groupDescriptors={this.userActivityUIGroups}
                        />
                      </section>
                    </div>
                  </div>
                )}
              </div>

              <footer className="footer-save" hidden={!securityWrite}>
                <button
                  disabled={
                    Object.keys(httpErrorAudit?.errors || {}).length > 0
                  }
                  className="margin-right-2"
                >
                  Save
                </button>
              </footer>
            </form>
          )}
        />
      </>
    );
  }

  formatTimeUnit(unit) {
    switch (unit) {
      case 'minutes':
        return 60;
      case 'hours':
        return 3600;
      case 'days':
        return 86400;
    }
  }

  prepareAuditDataForSending(parameters) {
    var value = this.form.group.getRawValue().auditEvents;
    var result = { auditdEnabled: value.auditdEnabled };
    var compatVersion55 = parameters[1];
    var isEnterprise = parameters[2];

    if (compatVersion55 && isEnterprise) {
      if (value.auditdEnabled && value.descriptors) {
        result.disabled = [];
        Object.keys(value.descriptors).forEach(function (key) {
          Object.keys(value.descriptors[key]).forEach(function (id) {
            !value.descriptors[key][id] && result.disabled.push(id);
          });
        });
        result.disabled = result.disabled.join(',');
      }
      var users = value.disabledUsers;
      result.disabledUsers =
        value.auditdEnabled && users
          ? users.replace(/\/couchbase/gi, '/local')
          : '';
    }
    if (value.auditdEnabled) {
      result.rotateInterval =
        value.rotateInterval * this.formatTimeUnit(value.rotateUnit);
      result.logPath = value.logPath;
      result.rotateSize = value.rotateSize;
    }
    if (value.auditdEnabled && value.rotateSize) {
      result.rotateSize = value.rotateSize * this.IEC.Mi;
    }
    return result;
  }

  prepareUserActivityDataForSending() {
    let value = this.form.group.getRawValue().userActivity;
    let result = {
      enabled: value.enabled,
      trackedRoles: [],
      trackedGroups: [],
    };
    if (value.roleDescriptors && value.enabled) {
      Object.values(value.roleDescriptors).forEach((descriptor) => {
        Object.entries(descriptor).forEach(([role, value]) => {
          if (value) {
            result.trackedRoles.push(role);
          }
        });
      });
    }
    if (value.groupDescriptors && value.enabled) {
      Object.keys(value.groupDescriptors).forEach((group) => {
        if (value.groupDescriptors[group]) {
          result.trackedGroups.push(group);
        }
      });
    }
    return result;
  }

  getDisabledByID(disabled) {
    return disabled.reduce(function (acc, item) {
      acc[item] = true;
      return acc;
    }, {});
  }

  getEnding(value) {
    return value != 1 ? 's' : '';
  }

  getDescriptorsByModule(data) {
    if (data[2]) {
      Array.prototype.push.apply(data[0], data[2]);
    }
    return data[0].reduce(function (acc, item) {
      acc[item.module] = acc[item.module] || [];
      item.value = !data[1][item.id];
      acc[item.module].push(item);
      return acc;
    }, {});
  }

  maybeDisableToggles(value) {
    var method = value ? 'enable' : 'disable';
    this.form.group
      .get('auditEvents.auditdEnabled')
      [method]({ emitEvent: false });
    this.form.group.get('userActivity.enabled')[method]({ emitEvent: false });
  }

  maybeDisableAuditFields(values) {
    var settings = { emitEvent: false };
    var method = values[1] && values[0] ? 'enable' : 'disable';
    this.form.group.get('auditEvents.logPath')[method](settings);
    this.form.group.get('auditEvents.rotateInterval')[method](settings);
    this.form.group.get('auditEvents.rotateSize')[method](settings);
    this.form.group.get('auditEvents.rotateUnit')[method](settings);
    this.form.group.get('auditEvents.disabledUsers')[method](settings);
  }

  unpackInfo(info) {
    var auditData;
    var userActivityData;
    var hasUserActivity = info instanceof Array;
    if (hasUserActivity) {
      auditData = info[0];
      userActivityData = info[1];
    } else {
      auditData = info;
    }

    if (auditData.rotateInterval % 86400 == 0) {
      auditData.rotateInterval /= 86400;
      auditData.rotateUnit = 'days';
    } else if (auditData.rotateInterval % 3600 == 0) {
      auditData.rotateInterval /= 3600;
      auditData.rotateUnit = 'hours';
    } else {
      auditData.rotateInterval /= 60;
      auditData.rotateUnit = 'minutes';
    }
    if (auditData.rotateSize) {
      auditData.rotateSize = auditData.rotateSize / this.IEC.Mi;
    }
    if (auditData.disabledUsers) {
      auditData.disabledUsers = auditData.disabledUsers
        .map(function (user) {
          return (
            user.name +
            '/' +
            (user.domain === 'local' ? 'couchbase' : user.domain)
          );
        })
        .join(',');
    }

    let result = { auditEvents: auditData };
    if (hasUserActivity) {
      result.userActivity = { enabled: userActivityData.enabled };
    }

    return result;
  }

  getUIUserRolesMap([uiRoles, userActivity]) {
    return uiRoles.folders.reduce((acc, item) => {
      item.roles.forEach((role) => {
        role.value = userActivity.trackedRoles.includes(role.role);
      });
      acc[item.name] = item.roles;
      return acc;
    }, {});
  }

  getUIUserGroupsMap([uiGroups, userActivity]) {
    return uiGroups.reduce((acc, item) => {
      acc[item.id] = {
        description: item.description,
        value: userActivity.trackedGroups.includes(item.id),
      };
      return acc;
    }, {});
  }
}
