import React from 'react';
import { Subject } from 'rxjs';
import { FormBuilder, FieldGroup } from 'react-reactive-form';
import { Dropdown, DropdownButton } from 'react-bootstrap';
import { MnInputFilterComponent } from './mn.input.filter.component.jsx';
import { MnHelperService } from './mn.helper.service.js';
import { MnLifeCycleHooksToStream } from './mn.core.js';

class MnSelectComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.hiddenRadioGroup = FormBuilder.group({ hiddenRadio: null });

    this.state = {
      disabled: false,
      value: null,
      preparedValues: [],
      preparedLabels: [],
      hasSearchInput: false,
      id: MnHelperService.generateID(),
    };

    this.selectOptionClickStream = new Subject();
    this.selectLabelClickStream = new Subject();

    this.selectOptionClickStream
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.optionSelected.bind(this));

    this.dropdownFormControl = props.group.get(props.mnFormControlName);
  }

  componentDidMount() {
    const { hasSearch } = this.props;

    if (hasSearch) {
      this.prepareSearch();
    }

    if (this.dropdownFormControl) {
      this.setState({ disabled: this.dropdownFormControl.disabled });
      this.dropdownFormControl.registerOnDisabledChange((disabled) =>
        this.setState({ disabled })
      );

      this.valueChanges = this.dropdownFormControl.valueChanges.pipe(
        startWith(this.dropdownFormControl.value)
      );
      this.valueChanges
        .pipe(distinctUntilChanged(), takeUntil(this.mnOnDestroy))
        .subscribe(this.setHiddenRadioValue.bind(this));
    }
  }

  prepareSearch() {
    const searchMinimumOptionsNumber = 10;
    this.searchFilter = MnHelperService.createFilter(this);

    const valuesStream = this.mnOnChanges.pipe(pluck('values', 'currentValue'));

    valuesStream
      .pipe(this.searchFilter.pipe, takeUntil(this.mnOnDestroy))
      .subscribe((preparedValues) => {
        this.setState({ preparedValues });
      });

    valuesStream
      .pipe(
        map(
          (values) =>
            (this.hasSearch &&
              (values || []).length >= searchMinimumOptionsNumber) ||
            false
        ),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe((hasSearchInput) => {
        this.setState({ hasSearchInput });
      });

    const labelsStream = this.mnOnChanges.pipe(pluck('labels', 'currentValue'));

    labelsStream
      .pipe(this.searchFilter.pipe, takeUntil(this.mnOnDestroy))
      .subscribe((preparedLabels) => {
        this.setState({ preparedLabels });
      });

    this.selectLabelClickStream
      .pipe(
        withLatestFrom(labelsStream, valuesStream),
        takeUntil(this.mnOnDestroy)
      )
      .subscribe(([selectedLabel, labels, values]) => {
        this.optionSelected(values[labels.indexOf(selectedLabel)]);
      });
  }

  setHiddenRadioValue(value) {
    const { hasSearch, labels, values } = this.props;
    const patchedValue =
      hasSearch && labels ? labels[values.indexOf(value)] : value;
    this.hiddenRadioGroup.patchValue({ hiddenRadio: patchedValue });
  }

  defaultValuesMapping(option) {
    const { capitalize } = this.props;
    if (capitalize && typeof option === 'string' && option) {
      return option[0].toUpperCase() + option.slice(1);
    }
    return option;
  }

  optionSelected(value) {
    const { hasSearchInput } = this.state;
    this.dropdownFormControl.setValue(value);
    if (hasSearchInput) {
      this.searchFilter.group.get('value').setValue('');
    }
  }

  render() {
    const {
      values,
      labels,
      valuesMapping = this.defaultValuesMapping.bind(this),
      mnPlaceholder,
      placement = 'bottom',
      hasSearch,
    } = this.props;
    const { id, disabled, preparedValues, preparedLabels, hasSearchInput } =
      this.state;

    return (
      <div class="mn-select relative">
        <DropdownButton
          id={`mn-select-${id}`}
          title={
            labels
              ? labels[values.indexOf(this.state.value)]
              : valuesMapping(this.state.value) || mnPlaceholder
          }
          disabled={disabled}
          drop={placement}
        >
          {hasSearchInput && (
            <MnInputFilterComponent
              group={this.searchFilter.group}
              mnPlaceholder="filter options"
              className="row flex-left sticky position-top-0"
            />
          )}
          <FieldGroup
            control={this.hiddenRadioGroup}
            render={() => (
              <div className="scrollable">
                {!hasSearchInput &&
                  values.map((value, i) => (
                    <Dropdown.Item
                      key={i}
                      as="button"
                      onClick={() => this.selectOptionClickStream.next(value)}
                    >
                      {labels ? labels[i] : valuesMapping(value)}
                    </Dropdown.Item>
                  ))}
                {hasSearchInput &&
                  !labels &&
                  preparedValues.map((value, i) => (
                    <Dropdown.Item
                      key={i}
                      as="button"
                      onClick={() => this.selectOptionClickStream.next(value)}
                    >
                      {valuesMapping(value)}
                    </Dropdown.Item>
                  ))}
                {hasSearchInput &&
                  labels &&
                  preparedLabels.map((label, i) => (
                    <Dropdown.Item
                      key={i}
                      as="button"
                      onClick={() => this.selectLabelClickStream.next(label)}
                    >
                      {label}
                    </Dropdown.Item>
                  ))}
              </div>
            )}
          />
        </DropdownButton>
      </div>
    );
  }
}

export { MnSelectComponent };
