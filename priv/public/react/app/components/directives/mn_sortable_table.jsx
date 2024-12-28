import React, { Component, createContext, forwardRef } from 'react';
import _ from 'lodash';

const MnSortableTableContext = createContext();

class MnSortableTableClass extends Component {
  constructor(props) {
    super(props);
    this.currentSortableTitle = null;
  }

  setOrderOrToggleInvert = (orderBy, name) => {
    if (this.isOrderBy(name)) {
      this.props.setState(prevState => ({ invert: !prevState.invert }));
    } else {
      this.props.setState({ invert: false });
    }
    this.setOrder(orderBy, name);
  };

  isOrderBy = (name) => {
    return this.currentSortableTitle === name;
  };

  setOrder = (orderBy, name) => {
    this.currentSortableTitle = name;
    this.props.setState({ orderBy });
  };

  orderBy = (collection) => {
    const rv = _.sortBy(collection, [this.props.state.orderBy]);
    return this.props.state.invert ? rv.reverse() : rv;
  };

  render() {
    return (
      <MnSortableTableContext.Provider
        value={{
          setOrderOrToggleInvert: this.setOrderOrToggleInvert,
          isOrderBy: this.isOrderBy,
          orderBy: this.orderBy,
          invert: this.props.state.invert
        }}
      >
        <div className={this.props.className}>
          {this.props.children}
        </div>
      </MnSortableTableContext.Provider>
    );
  }
}

const MnSortableTable = forwardRef((props, ref) => (
  <MnSortableTableClass
    {...props}
    ref={instance => {
      if (instance) {
        ref.current = {
          orderBy: instance.orderBy
        };
      }
    }}
  />
));

class MnSortableTitle extends Component {
  static contextType = MnSortableTableContext;

  componentDidMount() {
    const { setOrderOrToggleInvert } = this.context;
    if (this.props.sortByDefault) {
      setOrderOrToggleInvert(
        this.props.sortFunction || this.props.mnSortableTitle,
        this.props.mnSortableTitle
      );
    }
  }

  render() {
    const { setOrderOrToggleInvert, isOrderBy, invert } = this.context;
    const { mnSortableTitle, sortFunction, className } = this.props;
    const handleClick = () => {
      setOrderOrToggleInvert(sortFunction || mnSortableTitle, mnSortableTitle);
    };

    const dynamicActive = isOrderBy(mnSortableTitle);
    const dynamicInverted = dynamicActive && invert;

    return (
      <span
        onClick={handleClick}
        className={`${className} ${dynamicActive ? 'dynamic-active' : ''} ${dynamicInverted ? 'dynamic-inverted' : ''}`}
      >
        {this.props.children}
      </span>
    );
  }
}

export { MnSortableTable, MnSortableTitle, MnSortableTableContext };
