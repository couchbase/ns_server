/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import { UIRouter } from '../mn.react.router.js';
import mnPermissions from '../components/mn_permissions.js';
import mnUserRolesService from './mn_user_roles_service.js';
import mnStoreService from '../components/mn_store_service.js';
import { MnOverviewComponent } from './mn_overview_controller.jsx';
import { MnStatisticsNewComponent } from './mn_statistics_controller.jsx';

UIRouter.transitionService.onBefore(
  {
    from: (state) => state.name !== 'app.admin.overview.statistics',
    to: 'app.admin.overview.statistics',
  },
  (trans) => {
    var mnPermissionsService = mnPermissions;
    let original = Object.assign({}, trans.params());

    return Promise.all([
      mnPermissionsService.check(),
      mnUserRolesService.getUserProfile(),
    ]).then(function ([permissions]) {
      let params = Object.assign({}, original);
      var statsRead = permissions.bucketNames['.stats!read'];
      let scenarios = mnStoreService.store('scenarios').share();
      let groups = mnStoreService.store('groups').share();

      params.scenario =
        (params.scenario &&
          (scenarios.find((item) => item.id == params.scenario) || {}).id) ||
        (
          scenarios.find(
            (item) =>
              item.uiid == 'mn-cluster-overview' ||
              item.name == 'Cluster Overview'
          ) || {}
        ).id ||
        mnStoreService.store('scenarios').last().id;

      if (!original.openedGroups.length) {
        params.openedGroups = groups
          .filter(
            (g) =>
              g.uiid &&
              (g.uiid == 'mn-cluster-overview-group' ||
                g.uiid == 'mn-all-services-data-group')
          )
          .map((g) => g.id);
      }

      if (params.scenarioBucket && (!statsRead || !statsRead[0])) {
        params.scenarioBucket = null;
      }

      if (
        params.scenarioBucket !== original.scenarioBucket ||
        params.scenario !== original.scenario ||
        params.openedGroups.length !== original.openedGroups.length
      ) {
        return trans.router.stateService.target(
          'app.admin.overview.statistics',
          params
        );
      }
    });
  }
);

let overviewState = {
  name: 'app.admin.overview',
  url: '/overview',
  abstract: true,
  views: {
    'main@app.admin': {
      component: MnOverviewComponent,
    },
  },
  data: {
    title: 'Dashboard',
  },
};

let statisticsState = {
  name: 'app.admin.overview.statistics',
  url: '/stats?statsHostname',
  component: MnStatisticsNewComponent,
  params: {
    statsHostname: 'all',
  },
};

export const states = [overviewState, statisticsState];
