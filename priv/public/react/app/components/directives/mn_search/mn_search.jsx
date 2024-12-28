import React, { Component } from 'react';

class MnSearch extends Component {
  constructor(props) {
    super(props);
    this.state = {
      mnSearch: '',
      showFilterFlag: false,
      focusFilterField: false
    };
  }

  componentWillMount() {
    var vm = this;
    vm.hideFilter = hideFilter;
    vm.showFilter = showFilter;

    function hideFilter() {
      vm.setState({mnSearch: "", showFilterFlag: false});
    }

    function showFilter() {
      vm.setState({showFilterFlag: true, focusFilterField: true});
    }
  }

  render() {
    const vm = this;
    const { mnPlaceholder, mnHideButton, mnDisabled, className, onChange, mnSearch} = this.props;
    const { showFilterFlag, focusFilterField } = this.state;

    return (
      <div className={className}>
        {(showFilterFlag || mnHideButton) && (
          <div className="filter-input-group">
            <input
              type="text"
              value={mnSearch}
              onChange={(event) => onChange(event.target.value)}
              disabled={mnDisabled}
              maxLength="256"
              className="filter-input"
              placeholder={mnPlaceholder}
              autoFocus={focusFilterField}
            />
            <span className="icon fa-search-minus" style={{ display: !mnSearch ? '' : 'none' }}></span>
            <span className="icon fa-times-circle" style={{ display: mnSearch ? '' : 'none' }} onClick={() => onChange('')}></span>
          </div>
        )}
        <a
          onClick={vm.showFilter}
          style={{ display: !showFilterFlag && !mnHideButton ? '' : 'none' }}
          className="allcaps">filter
        </a>
        <a
          onClick={vm.hideFilter}
          style={{ display: showFilterFlag && !mnHideButton ? '' : 'none' }}
          className="allcaps">done
        </a>
      </div>
    );
  }
}

export { MnSearch };
