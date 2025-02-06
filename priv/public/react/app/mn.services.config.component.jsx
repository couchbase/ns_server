/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import { merge, fromEvent, BehaviorSubject } from 'rxjs';
import {
  takeUntil,
  map,
  withLatestFrom,
  filter,
  switchMap,
  first,
  throttleTime,
  distinctUntilChanged,
} from 'rxjs/operators';
import { FieldGroup, FieldControl } from 'react-reactive-form';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';

import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnPoolsService } from './mn.pools.service.js';
import { MnAdminService } from './mn.admin.service.js';
import { MnWizardService } from './mn.wizard.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnServicesConfigComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      postPoolsDefaultValidationError: null,
      postClusterInitHttpError: null,
      mnServices: null,
      total: null,
    };
  }

  componentWillUnmount() {
    super.componentWillUnmount();
    this.props.group.valueChanges.unsubscribe();
    this.props.group.get('flag').valueChanges.unsubscribe();
  }

  componentWillMount() {
    this.focusFieldSubject = new BehaviorSubject(true);
    this.postPoolsDefaultValidation =
      MnAdminService.stream.postPoolsDefaultValidation;
    this.postClusterInitHttp = MnWizardService.stream.postClusterInitHttp;
    this.isEnterprise = MnPoolsService.stream.isEnterprise;
    this.quotaServices = MnPoolsService.stream.quotaServices;
    this.mnServices = MnPoolsService.stream.mnServices;
    this.getServiceName = MnPoolsService.getServiceVisibleName;
    this.getServiceErrorName = MnPoolsService.getServiceQuotaName;

    // MnHelperReactService.mnFocus(this);

    this.postPoolsDefaultValidationError =
      this.postPoolsDefaultValidation.error;
    this.postClusterInitHttpError = this.postClusterInitHttp.error;

    MnHelperReactService.async(this, 'postPoolsDefaultValidationError');
    MnHelperReactService.async(this, 'postClusterInitHttpError');
    MnHelperReactService.async(this, 'mnServices');

    if (this.props.isFlagEnabled) {
      this.activateHotKeys();
    }
    if (!this.props.isFieldEnabled) {
      return;
    }
    this.focusFieldSubject = this.quotaServices.pipe(
      map(
        function (quotaServices) {
          return quotaServices.find(this.selectInitialFocus.bind(this));
        }.bind(this)
      )
    );

    if (this.props.isFlagEnabled && this.props.isFieldEnabled) {
      this.total = merge(
        MnHelperReactService.valueChanges(this.props.group.valueChanges),
        this.props.initDataStream
      ).pipe(
        withLatestFrom(this.quotaServices),
        map(this.calculateTotal.bind(this))
      );
      MnHelperReactService.async(this, 'total');
    }
    if (this.props.isFlagEnabled) {
      this.quotaServices.pipe(first()).subscribe(
        function (services) {
          services.forEach(this.createToggleFieldStream.bind(this));
        }.bind(this)
      );
    }

    MnHelperReactService.valueChanges(this.props.group.valueChanges)
      .pipe(
        throttleTime(500, undefined, { leading: true, trailing: true }),
        withLatestFrom(this.quotaServices),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe(this.validate.bind(this));

    this.props.initDataStream.subscribe((memoryQuota) => {
      this.props.group.get('field').patchValue(memoryQuota);
    });
  }

  selectInitialFocus(service) {
    return this.props.group.value.field[service];
  }

  calculateTotal(source) {
    return source[1].reduce(this.getQuota.bind(this), 0);
  }

  validate(source) {
    this.postPoolsDefaultValidation.post(
      source[1].reduce(this.packQuotas.bind(this), {})
    );
  }

  packQuotas(acc, name) {
    var service = this.getFlag(name);
    var keyName = name + 'MemoryQuota';
    switch (name) {
      case 'kv':
        keyName = 'memoryQuota';
        break;
      case 'n1ql':
        keyName = 'queryMemoryQuota';
        break;
    }
    if (!this.props.isFlagEnabled || (service && service.value)) {
      acc[keyName] = this.getField(name).value;
    }
    return acc;
  }

  getQuota(acc, name) {
    var flag = this.getFlag(name);
    var field = this.getField(name);
    return acc + (((!flag || flag.value) && Number(field.value)) || 0);
  }

  createToggleFieldStream(serviceGroupName) {
    var group = this.getFlag(serviceGroupName);
    if (group) {
      MnHelperReactService.valueChanges(group.valueChanges)
        .pipe(takeUntil(this.mnOnDestroy))
        .subscribe(this.toggleFields(serviceGroupName).bind(this));
    }
  }

  toggleFields(name) {
    return function () {
      this.getField(name)[this.getFlag(name).value ? 'enable' : 'disable']({
        onlySelf: true,
      });
    };
  }

  getFlag(name) {
    return this.props.group.get('flag.' + name);
  }

  getField(name) {
    return this.props.group.get('field.' + name);
  }

  activateHotKeys() {
    var altKey = merge(
      fromEvent(document, 'keyup'),
      fromEvent(document, 'keydown')
    ).pipe(
      map((evt) => evt.altKey),
      distinctUntilChanged()
    );

    var isPressed = altKey.pipe(filter((isPressed) => isPressed));
    var isNotPressed = altKey.pipe(filter((isPressed) => !isPressed));

    isPressed
      .pipe(
        switchMap(() =>
          MnHelperReactService.valueChanges(
            this.props.group.get('flag').valueChanges
          ).pipe(takeUntil(isNotPressed))
        ),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe((flag) => {
        let flags = this.props.group.get('flag').controls;
        let toggle = Object.values(flag).filter((v) => !v).length == 1;

        Object.keys(flag).forEach((key) => {
          flags[key].setValue(!toggle, { onlySelf: true });
        });
      });
  }

  render() {
    const { group } = this.props;
    const {
      postPoolsDefaultValidationError,
      postClusterInitHttpError,
      mnServices,
      total,
    } = this.state;

    return (
      <FieldGroup
        control={group}
        strict={false}
        render={() => (
          <div>
            <div
              className="error"
              hidden={!postPoolsDefaultValidationError?.errors?._}
            >
              {postPoolsDefaultValidationError?.errors?._}
            </div>
            <div
              className="error"
              hidden={!postClusterInitHttpError?.errors?.services}
            >
              {postClusterInitHttpError?.errors?.services}
            </div>

            {mnServices?.map((service) => (
              <div key={service}>
                <div className="row formrow">
                  {group.value.flag && (
                    <div className="width-6">
                      <FieldControl
                        strict={false}
                        name={`flag.${service}`}
                        render={({ handler }) => (
                          <>
                            <input
                              type="checkbox"
                              id={`${service}-ram-flag`}
                              {...handler('checkbox')}
                            />
                            <label
                              htmlFor={`${service}-ram-flag`}
                              className="checkbox"
                            >
                              {this.getServiceName(service)}
                              {service === 'n1ql' && (
                                <OverlayTrigger
                                  placement="right"
                                  overlay={
                                    <Tooltip>
                                      The memory quota for the Query service is
                                      a soft limit target that the garbage
                                      collector works to respect, including
                                      running more frequently as the limit is
                                      approached or crossed. When set to 0 the
                                      soft limit target is disabled and the
                                      garbage collector runs as normal.
                                    </Tooltip>
                                  }
                                >
                                  <span className="fa-stack icon-info margin-left-quarter">
                                    <span className="icon fa-circle-thin fa-stack-2x"></span>
                                    <span className="icon fa-info fa-stack-1x"></span>
                                  </span>
                                </OverlayTrigger>
                              )}
                            </label>
                          </>
                        )}
                      />
                    </div>
                  )}

                  {!group.value.flag && (
                    <label
                      htmlFor={`${service}-service-field`}
                      className="width-6"
                    >
                      {this.getServiceName(service)}
                    </label>
                  )}

                  {group.value.field && service === 'backup' && (
                    <small className="form-inline width-6 text-center">
                      - - - - - - -
                    </small>
                  )}

                  {group.value.field && service !== 'backup' && (
                    <div className="row width-6 flex-right relative">
                      <FieldControl
                        strict={false}
                        name={`field.${service}`}
                        render={({ handler }) => (
                          <input
                            id={`${service}-service-field`}
                            type="text"
                            // ref={(input) => this.input = input}
                            {...handler()}
                          />
                        )}
                      />
                      <div className="inside-label">MiB</div>
                    </div>
                  )}
                </div>

                <div
                  className="error"
                  hidden={
                    !postPoolsDefaultValidationError?.errors?.[
                      this.getServiceErrorName(service)
                    ]
                  }
                >
                  {
                    postPoolsDefaultValidationError?.errors?.[
                      this.getServiceErrorName(service)
                    ]
                  }
                </div>
                <div
                  className="error"
                  hidden={
                    !postClusterInitHttpError?.errors?.[
                      this.getServiceErrorName(service)
                    ]
                  }
                >
                  {
                    postClusterInitHttpError?.errors?.[
                      this.getServiceErrorName(service)
                    ]
                  }
                </div>
              </div>
            ))}

            {group.value.field && group.value.flag && (
              <div className="text-small text-right nowrap margin-right-1">
                <strong>TOTAL QUOTA</strong> &nbsp; {total}MiB
              </div>
            )}
          </div>
        )}
      />
    );
  }
}

export { MnServicesConfigComponent };
