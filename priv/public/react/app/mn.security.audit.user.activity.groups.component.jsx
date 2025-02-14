import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import {
  FormGroup,
  FormControl,
  FieldGroup,
  FieldControl,
} from 'react-reactive-form';
import { combineLatest, of } from 'rxjs';
import {
  pluck,
  distinctUntilChanged,
  takeUntil,
  startWith,
  map,
} from 'rxjs/operators';
import { pipe, all, equals } from 'ramda';
import { MnHelperReactService } from './mn.helper.react.service';

export class MnSecurityAuditUserActivityGroupsComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      isUserActivityEnabled: false,
      groupDescriptors: null,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    this.formHelper = new FormGroup({
      toggleAll: new FormControl(),
    });

    this.groupDescriptors = this.props.groupDescriptors.pipe(
      takeUntil(this.mnOnDestroy)
    );
    this.groupDescriptors.subscribe(this.generateForm.bind(this));
    MnHelperReactService.async(this, 'groupDescriptors');

    const groupDescriptorsGroup = this.props.group.get('groupDescriptors');

    this.groupChanges = MnHelperReactService.valueChanges(
      this,
      groupDescriptorsGroup.valueChanges
    ).pipe(
      startWith(groupDescriptorsGroup.getRawValue()),
      map(() => groupDescriptorsGroup.getRawValue())
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

    combineLatest(this.isUserActivityEnabled, this.groupDescriptors)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableFields.bind(this));

    this.groupChanges
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
      this.groupDescriptors
    )
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.doToggleAll.bind(this));
  }

  maybeDisableToggleAll(value) {
    const method = value ? 'enable' : 'disable';
    this.formHelper.get('toggleAll')[method]({ emitEvent: false });
  }

  maybeDisableFields([value]) {
    const controls = this.props.group.get('groupDescriptors').controls;
    Object.keys(controls).forEach((controlID) => {
      const method = value ? 'enable' : 'disable';
      controls[controlID][method]({ emitEvent: false });
    });
  }

  setToggleAllValue(value) {
    this.formHelper.get('toggleAll').setValue(value, { emitEvent: false });
  }

  doToggleAll([value]) {
    const groups = this.props.group.get('groupDescriptors');
    const ids = Object.keys(groups.value);
    groups.patchValue(
      ids.reduce((acc, key) => {
        acc[key] = value;
        return acc;
      }, {})
    );
  }

  generateForm(descriptors) {
    Object.keys(descriptors).forEach((group) => {
      this.props.group
        .get('groupDescriptors')
        .addControl(group, new FormControl(descriptors[group].value));
    });
  }

  render() {
    const { groupDescriptors } = this.state;

    if (!groupDescriptors || !Object.keys(groupDescriptors).length) {
      return null;
    }

    return (
      <section className="border-0">
        <div className="audit-module-body">
          <FieldGroup
            strict={false}
            control={this.formHelper}
            render={() => (
              <>
                <div className="row flex-left">
                  <label
                    className="toggle-control margin-0"
                    htmlFor="groups_checkall"
                  >
                    <FieldControl
                      strict={false}
                      name="toggleAll"
                      render={({ handler }) => {
                        return (
                          <input
                            type="checkbox"
                            id="groups_checkall"
                            {...handler('checkbox')}
                          />
                        );
                      }}
                    />
                    <span className="toggle-control-body"></span>
                  </label>
                  <span className="text-smaller">&nbsp; enable all</span>
                </div>
                <hr />
              </>
            )}
          />
          <FieldGroup
            strict={false}
            control={this.props.group.get('groupDescriptors')}
            render={() => (
              <>
                {Object.keys(groupDescriptors).map((item) => (
                  <div
                    key={item}
                    className="row flex-left items-top flex-gap-10"
                  >
                    <span className="fix-width-4">
                      <FieldControl
                        strict={false}
                        name={item}
                        render={({ handler }) => {
                          return (
                            <>
                              <input
                                type="checkbox"
                                id={`group_${item}`}
                                {...handler('checkbox')}
                              />
                              <label
                                className="checkbox"
                                htmlFor={`group_${item}`}
                              >
                                {item}
                              </label>
                            </>
                          );
                        }}
                      />
                    </span>
                    <p className="fix-width-5">
                      {groupDescriptors[item].description}
                    </p>
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
