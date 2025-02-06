import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { takeUntil, withLatestFrom } from 'rxjs/operators';
import { MnFormService } from './mn.form.service.js';
import { MnSpinner } from './components/directives/mn_spinner.jsx';
import { MnInputFilter } from './mn.input.filter.component.jsx';
import { MnHelperReactService } from './mn.helper.react.service.js';

class MnKeyspaceSelectorStep extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      step: null,
      list: null,
    };
  }

  componentDidMount() {
    const { service } = this.props;
    this.step = service.stream.step;
    this.list = service.stream.list;
    MnHelperReactService.async(this, 'step');
    MnHelperReactService.async(this, 'list');
  }

  render() {
    const { step, form, service } = this.props;

    return (
      this.state.step === step && (
        <div className="selector-scroll">
          <div style={{ minHeight: this.state.list ? null : '2.1rem' }}>
            {this.state.list ? (
              this.state.list.map((item) => (
                <a
                  key={item[service.filterKey]}
                  onClick={() => form.submit.next(item)}
                >
                  {item[service.filterKey]}
                </a>
              ))
            ) : (
              <MnSpinner mnSpinner={true} minHeight={'2.1rem'} />
            )}
          </div>
        </div>
      )
    );
  }
}

class MnKeyspaceSelector extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.form = MnFormService.create(this).setFormGroup({}).hasNoPostRequest();

    this.state = {
      showHideDropdown: false,
    };
  }

  componentDidMount() {
    const { defaults, service } = this.props;
    if (defaults) {
      service.setKeyspace(defaults);
    }

    this.form.submit
      .pipe(withLatestFrom(service.stream.step), takeUntil(this.mnOnDestroy))
      .subscribe(([item, step]) => {
        service.setResultItem(item, step);
      });

    service.stream.showHideDropdown
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe((showHideDropdown) => this.setState({ showHideDropdown }));
  }

  render() {
    const { service, className } = this.props;
    return (
      <div className={className} onClick={(e) => e.stopPropagation()}>
        <form onSubmit={() => this.form.submit.next()}>
          <div className="ks-control-wrapper">
            {service.options.steps.map((step) => (
              <MnInputFilter
                key={step}
                group={service.filters[step].group}
                mnFocusStatus={service.stream.onFocus[step]}
                mnFocus={service.stream.doFocus}
                mnClearDisabled={true}
                mnName={step}
                mnPlaceholder={`${step}...`}
              />
            ))}
          </div>
          {this.state.showHideDropdown &&
            service.options.steps.map((step) => (
              <MnKeyspaceSelectorStep
                key={step}
                step={step}
                service={service}
                form={this.form}
              />
            ))}
        </form>
      </div>
    );
  }
}

export { MnKeyspaceSelector };
