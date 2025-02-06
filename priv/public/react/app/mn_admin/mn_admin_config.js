import mnPoolDefault from '../components/mn_pool_default.js';
import mnPools from '../components/mn_pools.js';
import mnPermissions from '../components/mn_permissions.js';
import axios from 'axios';
import { MnAdminComponent } from './mn_admin_controller.jsx';

let cache;
function whoami() {
  if (cache) {
    return Promise.resolve(cache);
  }

  return axios.get('/whoami').then((response) => {
    cache = response.data;
    return cache;
  });
}

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
      resolveFn: () => whoami(),
    },
  ],
  component: MnAdminComponent,

  // views: {
  //   $default: {
  //     component: AdminComponent
  //   },
  //   'lostConnection@app.admin': {
  //     component: LostConnectionComponent
  //   }
  // }
};

export default adminState;
