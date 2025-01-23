import React from 'react';
import { Subject } from 'rxjs';
import { distinctUntilChanged, takeUntil, filter } from 'rxjs/operators';
import { MnLifeCycleHooksToStream } from '../mn.core.js';

import { UIRouter }  from "mn.react.router";
import { mnPoller } from '../components/mn_poll.js';
import mnGsiService from './mn_gsi_service.js';
import { MnKeyspaceSelectorService } from '../mn.keyspace.selector.service.js';
import { MnKeyspaceSelector } from '../mn.keyspace.selector.jsx';
import { MnElementCargo } from '../mn.element.crane.jsx';
import { MnSelect } from '../components/directives/mn_select/mn_select.jsx';
import { MnSearch } from '../components/directives/mn_search/mn_search.jsx';
import { MnGsiTable } from './mn_gsi_table_directive.jsx';
import mnPermissions from '../components/mn_permissions.js';
import { MnHelperReactService } from "../mn.helper.react.service.js";

class MnGsiComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      state: null,
      viewBy: UIRouter.globals.params.indexesView,
      filterField: '',
      rbac: null
    };
  }

  componentDidMount() {
    var vm = this;

    const { poolDefault } = this.props;

    vm.setIndexesView = setIndexesView;
    vm.onFilterChange = onFilterChange;

    vm.rbac = mnPermissions.export;
    MnHelperReactService.async(vm, "rbac");

    activate();

    function onFilterChange(value) {
      vm.setState({filterField: value});
    }

    function setIndexesView({selectedOption}) {
      UIRouter.stateService.go('.', {indexesView: selectedOption}).then(() => {
        vm.setState({viewBy: selectedOption});
        vm.poller.reload();
      })
    }

    function activate() {
      let mnOnDestroy = new Subject();

      vm.poller =
        new mnPoller(vm, () => {
          if (poolDefault.compat.atLeast70) {
            let params = vm.mnCollectionSelectorService.stream.result.getValue();
            // params.scope can actually be null. AngularJS code doesn't check for that.
            // and fails with "TypeError: Cannot read property 'name' of null" silently.
            // therefore the behaviour is different in React vs AngularJS.
            if (UIRouter.globals.params.indexesView == "viewByNode") {
              return mnGsiService.getIndexesStateByNodes(params);
            } else {
              return mnGsiService.getIndexesState(params);
            }
          } else {
            if (UIRouter.globals.params.indexesView == "viewByNode") {
              return mnGsiService.getIndexesStateByNodesMixed();
            } else {
              return mnGsiService.getIndexesStateMixed();
            }
          }
        })
        .setInterval(10000)
        .subscribe("state", vm)
        .reloadOnScopeEvent("indexStatusURIChanged");

      if (!poolDefault.compat.atLeast70) {
        vm.poller.reload();
        return;
      }

      vm.mnCollectionSelectorService =
        MnKeyspaceSelectorService.createCollectionSelector({
          component: {mnOnDestroy},
          steps: ["bucket", "scope"]
        });

      vm.mnCollectionSelectorService.stream.showHideDropdown
        .pipe(filter(v => !v),
              takeUntil(mnOnDestroy))
        .subscribe(stateGo);

      vm.$on("$destroy", function () {
        mnOnDestroy.next();
        mnOnDestroy.complete();
      });

      UIRouter.globals.params$
        .pipe(distinctUntilChanged((prev, curr) => 
              prev.commonBucket === curr.commonBucket && 
              prev.commonScope === curr.commonScope
            ), takeUntil(mnOnDestroy))
        .subscribe(params => {
          vm.mnCollectionSelectorService.setKeyspace({
            bucket: params.commonBucket,
            scope: params.commonScope
          });
        });

      if (!UIRouter.globals.params.commonBucket) {
        stateGo();
      }

      function stateGo() {
        vm.poller.reload();
        let params = vm.mnCollectionSelectorService.stream.result.getValue();
        UIRouter.stateService.go('.', {
          commonBucket: params.bucket ? params.bucket.name: null,
          commonScope: params.scope ? params.scope.name : null,
          commonCollection: null
        }, {notify: false});
      }
    }
  }

  render() {
    const vm = this;
    const { poolDefault } = vm.props;
    const { state, viewBy, filterField } = vm.state;

    if (!state) {
      return <div>Loading...</div>;
    }

    return <>
      <MnElementCargo depot='alerts'>
        {state?.warnings.map((message, index) => (
          <div key={index} className="interim alert alert-warning">
            <p>Warning: {message}</p>
          </div>
        ))}
      </MnElementCargo>
      {/* TODO: Add spinner
        <mn-main-spinner
        mn-spinner-value="!gsiCtl.state">
      </mn-main-spinner> */}
      <div style={{ paddingBottom: '120px' }}>
        <div className="row items-bottom margin-bottom-half flex-wrap">
          {poolDefault.compat.atLeast70 &&
            <div className="column flex-grow-1-5">
              <h5>Bucket & Scope</h5>
              <MnKeyspaceSelector className="mn-keyspace-selector" service={vm.mnCollectionSelectorService} />
            </div>}
          <MnSelect
            className="margin-right-half flex-grow-0"
            value={viewBy}
            onSelect={vm.setIndexesView}
            values={['viewByIndex', 'viewByNode']}
            labels={['view by index', 'view by server node']}
          />
          <MnSearch
            className="row flex-right flex-grow-1 margin-top-quarter"
            mnPlaceholder="filter indexes..."
            onChange={vm.onFilterChange}
            mnHideButton={true}
            mnSearch={filterField} />
        </div>

        {state?.indexes.length ? (
          <>
            {viewBy === 'viewByNode' && state.byNodes && (
              Object.entries(state.byNodes).map(([nodeName, group]) => (
                <div key={nodeName}>
                  <h4 className="margin-top-1-5">{nodeName}</h4>
                  <MnGsiTable
                    list={group}
                    rbac={vm.state.rbac}
                    nodeName={nodeName}
                    pools={vm.props.pools}
                    hideColumn="node"
                    filterField={filterField}
                  />
                </div>
              ))
            )} 
            {viewBy === 'viewByIndex' && (
              <MnGsiTable
                list={state.filtered}
                rbac={vm.state.rbac}
                pools={vm.props.pools}
                hideColumn="index"
                filterField={filterField}
              />
            )}
          </>
        ) : (
          <div className="zero-content">
            You have no GSI indexes yet.
          </div>
        )}
      </div>
    </>
  }
}

export { MnGsiComponent };
