import React from 'react';
import { MnLifeCycleHooksToStream } from 'mn.core';
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

export class MnSecurityAuditItemComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      toggleSection: false,
      isAuditEnabled: false,
      isThereEnabledField: false,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    this.onToggleClick = new Subject();

    this.formHelper = new FormGroup({
      toggleAll: new FormControl(),
    });

    this.toggleSection = this.onToggleClick.pipe(
      scan(not, false),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
    MnHelperReactService.async(this, 'toggleSection');

    this.descriptors = of(this.props.descriptors);
    this.thisDescriptors = this.descriptors.pipe(pluck(this.props.moduleName));
    MnHelperReactService.async(this, 'thisDescriptors');

    const thisDescriptorsByID = this.thisDescriptors.pipe(
      map((desc) =>
        desc.reduce((acc, item) => {
          acc[item.id] = item;
          return acc;
        }, {})
      )
    );

    combineLatest(this.thisDescriptors, thisDescriptorsByID)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.generateForm.bind(this));

    const thisModuleGroup = this.props.group
      .get('descriptors')
      .get(this.props.moduleName);

    this.thisModuleChanges = MnHelperReactService.valueChanges(
      this,
      thisModuleGroup.valueChanges
    ).pipe(
      startWith(thisModuleGroup.getRawValue()),
      map(() => thisModuleGroup.getRawValue())
    );

    this.isAuditEnabled = MnHelperReactService.valueChanges(
      this,
      this.props.group.valueChanges
    ).pipe(
      startWith(this.props.group.value),
      pluck('auditdEnabled'),
      distinctUntilChanged()
    );
    MnHelperReactService.async(this, 'isAuditEnabled');
    this.isAuditEnabled
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableToggleAll.bind(this));

    combineLatest(this.isAuditEnabled, thisDescriptorsByID)
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.maybeDisableFields.bind(this));

    this.isThereEnabledField = this.thisModuleChanges.pipe(
      map(pipe(Object.values, includes(true))),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
    MnHelperReactService.async(this, 'isThereEnabledField');

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

  maybeDisableFields([isEnabled, descriptorsById]) {
    const controls = this.props.group
      .get('descriptors')
      .get(this.props.moduleName).controls;
    Object.keys(controls).forEach((controlID) => {
      const method =
        !descriptorsById[controlID].nonFilterable && isEnabled
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
      .get('descriptors')
      .get(this.props.moduleName);
    const ids = Object.keys(thisModule.value);
    thisModule.patchValue(
      ids.reduce((acc, key) => {
        acc[key] = descriptorsById[key].nonFilterable || value;
        return acc;
      }, {})
    );
  }

  generateForm([descriptors, descriptorsById]) {
    this.props.group.get('descriptors').addControl(
      this.props.moduleName,
      new FormGroup(
        descriptors.reduce((acc, item) => {
          acc[item.id] = new FormControl({
            value: item.value,
            disabled: descriptorsById[item.id].nonFilterable,
          });
          return acc;
        }, {})
      )
    );
  }

  mapNames(name) {
    switch (name) {
      case 'auditd':
        return 'Audit';
      case 'ns_server':
        return 'REST API';
      case 'n1ql':
        return 'Query and Index Service';
      case 'eventing':
        return 'Eventing Service';
      case 'memcached':
        return 'Data Service';
      case 'xdcr':
        return name.toUpperCase();
      case 'fts':
        return 'Search Service';
      case 'view_engine':
        return 'Views';
      default:
        return name.charAt(0).toUpperCase() + name.substr(1).toLowerCase();
    }
  }

  render() {
    const {
      toggleSection,
      isAuditEnabled,
      isThereEnabledField,
      thisDescriptors,
    } = this.state;
    const { moduleName } = this.props;

    if (!thisDescriptors || !Array.isArray(thisDescriptors)) {
      return null;
    }

    return (
      <section
        className={`audit-module ${toggleSection ? 'audit-module-open' : ''}`}
      >
        <div
          className={`audit-module-header fix-width-6 ${isThereEnabledField && isAuditEnabled ? 'blue-bg-8' : ''}`}
        >
          <span
            className={`disclosure inline ${toggleSection ? 'disclosed' : ''}`}
            onClick={() => this.onToggleClick.next()}
          >
            {this.mapNames(moduleName)}
          </span>
          <span
            className={`icon ${isThereEnabledField ? 'fa-check green-3' : 'fa-ban red-4'}`}
            hidden={!isAuditEnabled}
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
            control={this.props.group.get('descriptors').get(moduleName)}
            render={() => (
              <>
                {thisDescriptors.map((desc) => (
                  <div
                    key={desc.id}
                    className="row flex-left items-top flex-gap-10"
                  >
                    <span className="fix-width-5">
                      <FieldControl
                        strict={false}
                        name={desc.id.toString()}
                        render={({ handler }) => {
                          return (
                            <>
                              <input
                                type="checkbox"
                                id={`thisModule_${moduleName}${desc.id}`}
                                {...handler('checkbox')}
                              />
                              <label
                                className="checkbox"
                                htmlFor={`thisModule_${moduleName}${desc.id}`}
                              >
                                {desc.name}
                              </label>
                            </>
                          );
                        }}
                      />
                    </span>
                    <p className="fix-width-4">{desc.description}</p>
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
