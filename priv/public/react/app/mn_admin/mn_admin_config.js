import mnPoolDefault from '../components/mn_pool_default.js';
import mnPools from '../components/mn_pools.js';
import mnPermissions from '../components/mn_permissions.js';
import { MnAdminComponent } from './mn_admin_controller.jsx';
import mnAuthService from '../mn_auth/mn_auth_service.js';
import { MnLostConnectionComponent } from './mn_lost_connection_config.jsx';

const adminState = {
  name: 'app.admin',
  url: '?commonBucket&scenarioBucket&commonScope&commonCollection&scenarioZoom&scenario',
  abstract: true,
  data: {
    requiresAuth: true,
  },
  params: {
    openedGroups: {
      value: [],
      array: true,
      dynamic: true,
    },
    scenarioBucket: {
      value: null,
      dynamic: true,
    },
    commonBucket: {
      value: null,
      dynamic: true,
    },
    commonScope: {
      value: null,
      dynamic: true,
    },
    commonCollection: {
      value: null,
      dynamic: true,
    },
    scenario: {
      value: null,
      dynamic: true,
    },
    scenarioZoom: {
      value: 'minute',
    },
  },
  resolve: [
    {
      token: 'poolDefault',
      deps: [],
      resolveFn: () => mnPoolDefault.getFresh(),
    },
    {
      token: 'pools',
      deps: [],
      resolveFn: () => mnPools.get(),
    },
    {
      token: 'permissions',
      deps: [],
      resolveFn: () => mnPermissions.check(),
    },
    {
      token: 'whoami',
      deps: [],
      resolveFn: () => mnAuthService.whoami(),
    },
  ],
  views: {
    $default: {
      component: MnAdminComponent,
    },
    'lostConnection@app.admin': {
      component: MnLostConnectionComponent,
    },
  },
};

export default adminState;
