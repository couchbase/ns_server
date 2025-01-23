/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import React from 'react';
import { mnPoller } from "../components/mn_poll.js";
import mnHelper from "../components/mn_helper.js";
import mnPoolDefault from "../components/mn_pool_default.js";
import mnServersService from "./mn_servers_service.js";
import { UIRouter } from 'mn.react.router';
import { MnLifeCycleHooksToStream } from '../mn.core.js';
import { UIView, UISref } from "@uirouter/react";
import { MnElementCargo } from '../mn.element.crane.jsx';
import { MnHelperReactService } from '../mn.helper.react.service.js';
import { MnMainSpinner } from '../components/directives/mn_main_spinner.jsx';
import mnPermissions from "../components/mn_permissions.js";
import mnBucketsService from "./mn_buckets_service.js";

class MnOverviewComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      nodes: null,
      tasks: null,
      rbac: null,
      buckets: null
    };
  }

  componentWillMount() {
    var vm = this;

    vm.getEndings = mnHelper.getEndings;
    vm.addressFamily = mnPoolDefault.export.getValue().thisNode.addressFamily;
    vm.addressFamilyOnly = mnPoolDefault.export.getValue().thisNode.addressFamilyOnly;
    vm.nodeEncryption = mnPoolDefault.export.getValue().thisNode.nodeEncryption;
    vm.implementationVersion = this.props.pools.implementationVersion;

    vm.buckets = mnBucketsService.export;
    MnHelperReactService.async(vm, "buckets");

    vm.rbac = mnPermissions.export;
    MnHelperReactService.async(vm, "rbac");

    vm.tasks= MnHelperReactService.tasks;
    MnHelperReactService.async(vm, "tasks");

    activate();

    function activate() {
      new mnPoller(vm, function () {
        return mnServersService.getServicesStatus(mnPoolDefault.export.getValue().isEnterprise);
      })
        .reloadOnScopeEvent("nodesChanged")
        .subscribe("nodes", vm)
        .cycle();
    }
  }

  render() {
    const { nodes, tasks, rbac, buckets } = this.state;
    const { pools, poolDefault } = this.props;

    return (
      <>
        <MnElementCargo depot="header">
          <div className="about-text resp-hide-sml">
            {pools.implementationVersion} 
            {this.addressFamily === 'inet6' && <span>&#8231; IPv6</span>}
            {this.addressFamily === 'inet' && <span>&#8231; IPv4</span>}
            {this.addressFamilyOnly && <span>-only</span>}
            {this.nodeEncryption && <span>&#8231; encrypted</span>}
            &nbsp; © 2025 <a href="https://couchbase.com" target="_blank" rel="noopener noreferrer">Couchbase, Inc.</a>
          </div>
        </MnElementCargo>

        <MnMainSpinner value={!nodes || (rbac.cluster.bucket['.'].settings.read && !buckets.details)} />

        <div className="margin-top-quarter padding-bottom-6">
          {!buckets.details?.length ? (
            <div className="zero-content">
              You have no data buckets.
              {rbac.cluster.buckets.create && (
                <span>
                  Go to <UISref to="app.admin.buckets"><a>Buckets</a></UISref> to add one, or load a
                  sample bucket with data & indexes from Settings {'>'} <UISref to="app.admin.settings.sampleBuckets"><a>Sample Buckets</a></UISref>.
                </span>
              )}
            </div>
          ) : <UIView />
          }
        </div>

        <footer className="footer-dashboard">
          <div className="service-widget-row resp-margin-xsml">
            <div 
              className={`service-widget dynamic_${nodes?.kv.statusClass}`} 
              onClick={() => UIRouter.stateService.go('app.admin.buckets')}>
              <p>Data - {buckets.details.length} bucket{this.getEndings(buckets.details.length)}</p>
              {Object.entries(nodes?.kv.nodesByStatuses || {}).map(([status, count]) => (
                <div key={status} className="error piped">
                  {count} node{this.getEndings(count)} {status}
                </div>
              ))}
            </div>

            <div 
              className={`service-widget dynamic_${nodes?.index.statusClass}`}
              onClick={() => UIRouter.stateService.go('app.admin.gsi')}>
              <p>Index</p>
              {Object.entries(nodes?.index.nodesByStatuses || {}).map(([status, count]) => (
                <div key={status} className="error piped">
                  {count} node{this.getEndings(count)} {status}
                </div>
              ))}
            </div>

            <div 
              className={`service-widget dynamic_${nodes?.n1ql.statusClass}`}
              onClick={() => UIRouter.stateService.go('app.admin.query.monitoring')}>
              <p>Query</p>
              {Object.entries(nodes?.n1ql.nodesByStatuses || {}).map(([status, count]) => (
                <div key={status} className="error piped">
                  {count} node{this.getEndings(count)} {status}
                </div>
              ))}
            </div>

            <div 
              className={`service-widget dynamic_${nodes?.fts.statusClass}`}
              onClick={() => UIRouter.stateService.go('app.admin.search.fts_list')}>
              <p>Search</p>
              {Object.entries(nodes?.fts.nodesByStatuses || {}).map(([status, count]) => (
                <div key={status} className="error piped">
                  {count} node{this.getEndings(count)} {status}
                </div>
              ))}
            </div>

            {poolDefault.isEnterprise && (
              <div 
                className={`service-widget dynamic_${nodes?.cbas.statusClass}`}
                onClick={() => UIRouter.stateService.go('app.admin.cbas.workbench')}>
                <p>Analytics</p>
                {Object.entries(nodes?.cbas.nodesByStatuses || {}).map(([status, count]) => (
                  <div key={status} className="error piped">
                    {count} node{this.getEndings(count)} {status}
                  </div>
                ))}
              </div>
            )}

            {poolDefault.isEnterprise && (
              <div 
                className={`service-widget dynamic_${nodes?.eventing.statusClass}`}
                onClick={() => UIRouter.stateService.go('app.admin.eventing.summary')}>
                <p>Eventing</p>
                {Object.entries(nodes?.eventing.nodesByStatuses || {}).map(([status, count]) => (
                  <div key={status} className="error piped">
                    {count} node{this.getEndings(count)} {status}
                  </div>
                ))}
              </div>
            )}

            {rbac.cluster.xdcr.remote_clusters.read && (
              <div 
                className={`service-widget dynamic_${tasks?.tasksXDCR.length ? 'healthy' : 'inactive'}`}
                onClick={() => UIRouter.stateService.go('app.admin.replications')}>
                <p>XDCR</p>
              </div>
            )}
          </div>

          <div className="dashboard-servers resp-xsml">
            <div className="dashboard-node" title="active nodes">
              <span className="icon fa-server green-2"></span>
              <p>
                {(nodes?.all.active.length || '0')} active node{this.getEndings(nodes?.all.active.length)}
              </p>
            </div>

            <div className="dashboard-node" title="failed-over nodes">
              <span className="icon fa-server orange-2"></span>
              <p>
                {(nodes?.all.failedOver.length || '0')} failed-over node{this.getEndings(nodes?.all.failedOver.length)}
              </p>
            </div>

            <div className="dashboard-node" title="nodes pending rebalance">
              <span className="icon fa-server orange-2"></span>
              <p>
                {(nodes?.all.pending.length || '0')} node{this.getEndings(nodes?.all.pending.length)} pending rebalance
              </p>
            </div>

            <div className="dashboard-node" title="inactive nodes">
              <span className="icon fa-server red-3"></span>
              <p>
                {(nodes?.all.down.length || '0')} inactive node{this.getEndings(nodes?.all.down.length)}
              </p>
            </div>
          </div>
        </footer>
      </>
    );
  }
}

export { MnOverviewComponent };
