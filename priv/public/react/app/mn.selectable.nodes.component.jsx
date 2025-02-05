import React from 'react';
import { Subject } from 'rxjs';
import { takeUntil, withLatestFrom } from 'rxjs/operators';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnFormatServices } from './mn.pipes.js';
import { MnHelperService } from './mn.helper.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { MnServerGroupsService } from './mn.server.groups.service.js';
import { MnSelectableNodeItemComponent } from './mn.selectable.node.item.component.jsx';
import { MnInputFilter } from './mn.input.filter.component.jsx';
import { MnSpinner } from './components/directives/mn_spinner.jsx';

class MnSelectableNodesComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      nodes: null,
      togglerState: false,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    // Create filter
    this.filter = MnHelperService.createFilter(
      this,
      ['hostname', 'groupName', 'services', 'status'],
      true,
      this.prepareFilteredValue.bind(this)
    );

    let nodesWithGroupName =
      MnServerGroupsService.stream.maybeGetServersWithGroups;
    this.nodes = nodesWithGroupName.pipe(this.filter.pipe);
    MnHelperReactService.async(this, 'nodes');

    if (this.props.mnSelectAll) {
      // Create toggler for select all
      this.toggler = MnHelperService.createToggle();
      // Subscribe to toggler state
      this.toggler.state
        .pipe(withLatestFrom(this.nodes), takeUntil(this.mnOnDestroy))
        .subscribe(this.toggleAllNodes.bind(this));
    }

    this.doFocusFilter = new Subject();
    this.doFocusFilter.next('filter');
  }

  toggleAllNodes([isChecked, filteredNodes]) {
    let nodeValues = this.props.mnGroup.value;
    filteredNodes.forEach((node) => {
      if (!this.props.mnGroup.controls[node.otpNode].disabled) {
        nodeValues[node.otpNode] = isChecked;
      }
    });
    this.props.mnGroup.patchValue(nodeValues);
    this.setState({ togglerState: isChecked });
  }

  trackByMethod(index, node) {
    return node.otpNode;
  }

  prepareFilteredValue(key, value) {
    if (key === 'services') {
      return value.map(MnFormatServices.transform).join(' ');
    }

    return value;
  }

  render() {
    const { mnGroup, mnSelectAll } = this.props;
    const { nodes, togglerState } = this.state;

    if (!this.filter) {
      return <MnSpinner mnSpinnerValue={true} />;
    }

    return (
      <div className="selectable-nodes-list">
        <MnSpinner mnSpinnerValue={!nodes} />

        <div className="row margin-bottom-half">
          {mnSelectAll && (
            <span className="row nodes-list-select-all">
              <input
                type="checkbox"
                id="thisModule_checkall"
                checked={togglerState}
                onChange={() => this.toggler.click.next()}
              />
              <label htmlFor="thisModule_checkall">select all</label>
            </span>
          )}

          <MnInputFilter
            className="row filter-log"
            group={this.filter.group}
            mnFocus={this.doFocusFilter}
            mnName="filter"
            mnPlaceholder="filter nodes..."
            mnClearDisabled={false}
          />
        </div>

        {nodes?.map((node, i) => (
          <section key={this.trackByMethod(i, node)} className="cbui-table">
            <MnSelectableNodeItemComponent
              mnGroup={mnGroup}
              mnSelectableNode={node}
            />
          </section>
        ))}

        {nodes?.length === 0 && (
          <div className="zero-content">No nodes match this filter term.</div>
        )}
      </div>
    );
  }
}

export { MnSelectableNodesComponent };
