import React from 'react';
import { Dropdown } from 'react-bootstrap';
import { MnLifeCycleHooksToStream } from 'mn.core';
import mnHelper from '../../mn_helper.js';
import { MnSearch } from '../mn_search/mn_search.jsx';

class MnSelect extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state ={
      isOpened: false,
      mnSearchValue: "",
    }
  }

  componentWillMount() {
    var vm = this;
    var searchMinimumOptionsNumber = 10;
    vm.id = mnHelper.generateID();

    vm.valuesMapping = vm.props.valuesMapping || defaultValuesMapping;
    vm.mnHorizontalAlign = vm.props.mnHorizontalAlign || "left";

    vm.optionClicked = optionClicked;
    vm.clickSearch = clickSearch;
    vm.getPreparedValues = getPreparedValues;
    vm.hasSearchInput = hasSearchInput;

    /**
     * Default values mapping:
     * * if capitalize input flag is true - capitalize the displayed option if it is a string
     * * else leave the option as it is
     * @param option
     * @returns {string}
     */
    function defaultValuesMapping(option) {
      if (vm.props.capitalize && typeof option === 'string' && option) {
        return option.charAt(0).toUpperCase() + option.slice(1);
      }

      return option;
    }

    function getPreparedValues() {
      vm.preparedValues = vm.props.labels ? vm.props.labels : (vm.props.values || []).map(vm.valuesMapping);
      return vm.preparedValues;
    }

    function optionClicked(value, event) {
      if (event && event.key !== 'Enter') {
        return;
      }

      vm.props.onSelect && vm.props.onSelect({selectedOption: value});
      vm.setState({"isOpened": false});

      if (vm.hasSearchInput()) {
        vm.setState({mnSearchValue: ""});
      }
    }

    function clickSearch(event) {
      event.stopPropagation();
    }

    function hasSearchInput() {
      return (vm.props.hasSearch && (vm.props.values || []).length >= searchMinimumOptionsNumber) || false;
    }
  }

  render() {
    const vm = this;
    const {
      values,
      labels,
      value,
      mnDisabled,
      openOnTop,
      mnPlaceholder,
      className
    } = this.props;

    const { isOpened, mnSearchValue } = this.state;

    return (
      <div className={`${className} uib-dropdown-menu`}>
        <Dropdown
          className={`mn-select relative min-width-3-5 ${vm.mnHorizontalAlign === 'left' ? 'mn-align-left' : ''} ${vm.mnHorizontalAlign === 'right' ? 'mn-align-right' : ''} ${openOnTop ? 'open-on-top' : ''}`}
          show={isOpened}
          onToggle={() => vm.setState({ isOpened: !isOpened })}
        >
          <Dropdown.Toggle
            disabled={mnDisabled}
            title={values.indexOf(value) >= 0 ? (labels ? labels[values.indexOf(value)] : vm.valuesMapping(value)) : (mnPlaceholder || '')}
            className={`outline btn-small dropdown-btn ellipsis ${isOpened ? 'active' : ''}`}
          >
            {values.indexOf(value) >= 0 ? (labels ? labels[values.indexOf(value)] : vm.valuesMapping(value)) : (mnPlaceholder || '')}
          </Dropdown.Toggle>
          <Dropdown.Menu className="panel absolute fit-content-width margin-0" uib-dropdown-menu="true">
            {vm.hasSearchInput() && 
              <MnSearch
                className="sticky position-top-0"
                onChange={(value) => vm.setState({ mnSearchValue: value })}
                onClick={vm.clickSearch}
                mnHideButton={true}
                mnSearch={mnSearchValue} />
            }
            <div className="scrollable">
              {!vm.hasSearchInput() && values.map((value, index) => (
                <div key={index} className="block option">
                  <input
                    type="radio"
                    id={`mn-select-${vm.id}-${index}`}
                    name={`mn-select-${vm.id}`}
                    checked={vm.props.value === value}
                    onChange={() => vm.optionClicked(value)}
                  />
                  <label
                    htmlFor={`mn-select-${vm.id}-${index}`}
                    className="width-12"
                    tabIndex="0"
                    onKeyDown={(e) => vm.optionClicked(value, e)}
                  >
                    {labels ? labels[index] : vm.valuesMapping(value)}
                  </label>
                </div>
              ))}
              {vm.hasSearchInput() && !labels && vm.getPreparedValues().filter(val => val.includes(mnSearchValue)).map((value, index) => (
                <div key={index} className="block option">
                  <input
                    type="radio"
                    id={`mn-select-${vm.id}-${index}`}
                    name={`mn-select-${vm.id}`}
                    checked={vm.props.value === vm.props.values[vm.preparedValues.indexOf(value)]}
                    onChange={() => vm.optionClicked(vm.props.values[vm.preparedValues.indexOf(value)])}
                  />
                  <label
                    htmlFor={`mn-select-${vm.id}-${index}`}
                    className="width-12"
                    tabIndex="0"
                    onKeyDown={(e) => vm.optionClicked(vm.props.values[vm.preparedValues.indexOf(value)], e)}
                  >
                    {value}
                  </label>
                </div>
              ))}
              {vm.hasSearchInput() && labels && labels.filter(label => label.includes(mnSearchValue)).map((label, index) => (
                <div key={index} className="block option">
                  <input
                    type="radio"
                    id={`mn-select-${vm.id}-${index}`}
                    name={`mn-select-${vm.id}`}
                    checked={vm.props.value === vm.props.values[labels.indexOf(label)]}
                    onChange={() => vm.optionClicked(vm.props.values[labels.indexOf(label)])}
                  />
                  <label
                    htmlFor={`mn-select-${vm.id}-${index}`}
                    className="width-12"
                    tabIndex="0"
                    onKeyDown={(e) => vm.optionClicked(vm.props.values[labels.indexOf(label)], e)}
                  >
                    {label}
                  </label>
                </div>
              ))}
            </div>
          </Dropdown.Menu>
        </Dropdown>
      </div>
    );
  }
}

export { MnSelect };