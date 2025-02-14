import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import {
  FormGroup,
  FormControl,
  FieldGroup,
  FieldControl,
} from 'react-reactive-form';
import { Subject, combineLatest, of } from 'rxjs';
import {
  pluck,
  scan,
  distinctUntilChanged,
  shareReplay,
  takeUntil,
  startWith,
  map,
} from 'rxjs/operators';
import { not, pipe, includes, all, equals } from 'ramda';
import { MnHelperReactService } from './mn.helper.react.service';

export class MnSecurityAuditUserActivityRoleComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      toggleSection: false,
      isFieldEnabled: false,
      isUserActivityEnabled: false,
      thisDescriptors: null,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    this.onToggleClick = new Subject();
    this.toggleSection = this.onToggleClick.pipe(
      scan(not, false),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
    MnHelperReactService.async(this, 'toggleSection');

    this.formHelper = new FormGroup({
      toggleAll: new FormControl(),
    });

    this.thisDescriptors = this.props.roleDescriptors.pipe(
      pluck(this.props.moduleName)
    );
    MnHelperReactService.async(this, 'thisDescriptors');

    const thisDescriptorsByID = this.thisDescriptors.pipe(
      map((desc) =>
        desc.reduce((acc, item) => {
          acc[item.role] = item;
          return acc;
        }, {})
      )
    );

    this.thisDescriptors
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.generateForm.bind(this));

    const thisModuleGroup = this.props.group
      .get('roleDescriptors')
      .get(this.props.moduleName);

    this.thisModuleChanges = MnHelperReactService.valueChanges(
      this,
      thisModuleGroup.valueChanges
    ).pipe(
      startWith(thisModuleGroup.getRawValue()),
      map(() => thisModuleGroup.getRawValue())
    );

    this.isUserActivityEnabled = MnHelperReactService.valueChanges(
      this,
      this.props.group.valueChanges
    ).pipe(
      startWith(this.props.group.value),
      pluck('enabled'),
      distinctUntilChanged()
    );
    MnHelperReactService.async(this, 'isUserActivityEnabled');

    this.isUserActivityEnabled
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableToggleAll.bind(this));

    combineLatest(this.isUserActivityEnabled, thisDescriptorsByID)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableFields.bind(this));

    this.isFieldEnabled = this.thisModuleChanges.pipe(
      map(pipe(Object.values, includes(true))),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
    MnHelperReactService.async(this, 'isFieldEnabled');

    this.thisModuleChanges
      .pipe(
        map(pipe(Object.values, all(equals(true)))),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe(this.setToggleAllValue.bind(this));

    combineLatest(
      MnHelperReactService.valueChanges(
        this,
        this.formHelper.get('toggleAll').valueChanges
      ),
      thisDescriptorsByID
    )
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.doToggleAll.bind(this));
  }

  maybeDisableToggleAll(value) {
    const method = value ? 'enable' : 'disable';
    this.formHelper.get('toggleAll')[method]({ emitEvent: false });
  }

  maybeDisableFields([value, descriptorsById]) {
    const controls = this.props.group
      .get('roleDescriptors')
      .get(this.props.moduleName).controls;
    Object.keys(controls).forEach((controlID) => {
      const method =
        !descriptorsById[controlID].nonFilterable && value
          ? 'enable'
          : 'disable';
      controls[controlID][method]({ emitEvent: false });
    });
  }

  setToggleAllValue(value) {
    this.formHelper.get('toggleAll').setValue(value, { emitEvent: false });
  }

  doToggleAll([value, descriptorsById]) {
    const thisModule = this.props.group
      .get('roleDescriptors')
      .get(this.props.moduleName);
    const ids = Object.keys(thisModule.value);
    thisModule.patchValue(
      ids.reduce((acc, key) => {
        acc[key] = descriptorsById[key].nonFilterable || value;
        return acc;
      }, {})
    );
  }

  generateForm(descriptors) {
    this.props.group.get('roleDescriptors').addControl(
      this.props.moduleName,
      new FormGroup(
        descriptors.reduce((acc, item) => {
          acc[item.role] = new FormControl(item.value);
          return acc;
        }, {})
      )
    );
  }

  render() {
    const {
      toggleSection,
      isFieldEnabled,
      isUserActivityEnabled,
      thisDescriptors,
    } = this.state;
    const { moduleName } = this.props;

    if (!thisDescriptors) {
      return null;
    }

    return (
      <section
        className={`audit-module ${toggleSection ? 'audit-module-open' : ''}`}
      >
        <div
          className={`audit-module-header fix-width-6 ${
            isFieldEnabled && isUserActivityEnabled ? 'blue-bg-8' : ''
          }`}
        >
          <span
            className={`disclosure inline ${toggleSection ? 'disclosed' : ''}`}
            onClick={() => this.onToggleClick.next()}
          >
            {moduleName}
          </span>
          <span
            className={`icon ${isFieldEnabled ? 'fa-check green-3' : 'fa-ban red-4'}`}
            hidden={!isUserActivityEnabled}
          ></span>
        </div>
        <div className="audit-module-body" hidden={!toggleSection}>
          <FieldGroup
            strict={false}
            control={this.formHelper}
            render={() => (
              <div className="row flex-left">
                <label
                  className="toggle-control margin-0"
                  htmlFor={`thisModule_checkall_${moduleName}`}
                >
                  <FieldControl
                    strict={false}
                    name="toggleAll"
                    render={({ handler }) => (
                      <input
                        type="checkbox"
                        id={`thisModule_checkall_${moduleName}`}
                        {...handler('checkbox')}
                      />
                    )}
                  />
                  <span className="toggle-control-body"></span>
                </label>
                <span className="text-smaller">&nbsp; enable all</span>
              </div>
            )}
          />
          <hr />
          <FieldGroup
            strict={false}
            control={this.props.group.get('roleDescriptors').get(moduleName)}
            render={() => (
              <>
                {thisDescriptors.map((item) => (
                  <div
                    key={item.role}
                    className="row flex-left items-top flex-gap-10"
                  >
                    <span className="fix-width-4">
                      <FieldControl
                        strict={false}
                        name={item.role}
                        render={({ handler }) => {
                          return (
                            <>
                              <input
                                type="checkbox"
                                id={`role_${moduleName}_${item.role}`}
                                {...handler('checkbox')}
                              />
                              <label
                                className="checkbox"
                                htmlFor={`role_${moduleName}_${item.role}`}
                              >
                                {item.name}
                              </label>
                            </>
                          );
                        }}
                      />
                    </span>
                    <p className="fix-width-5">{item.desc}</p>
                  </div>
                ))}
              </>
            )}
          />
        </div>
      </section>
    );
  }
}
