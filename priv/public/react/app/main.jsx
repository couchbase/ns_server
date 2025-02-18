import React from 'react';
import ReactDOM from 'react-dom';
import { UIRouter, UIView } from '@uirouter/react';
import { UIRouter as router } from 'mn.react.router';
import adminState from './mn_admin/mn_admin_config.js';
import appState from './app_config';

const authState = {
  name: 'app.auth.**',
  url: '/auth',
  lazyLoad: () => import('./mn.auth.states'),
};

const gsiState = {
  name: 'app.admin.gsi.**',
  url: '/index',
  lazyLoad: () => import('./mn_admin/mn_gsi_states'),
};

const wizardState = {
  name: 'app.wizard.**',
  lazyLoad: () => import('./mn.wizard.states'),
};

const overviewState = {
  name: 'app.admin.overview.**',
  url: '/overview',
  lazyLoad: () => import('./mn_admin/mn_overview_states.js'),
};

const securityState = {
  name: 'app.admin.security.**',
  url: '/security',
  lazyLoad: () => import('./mn_admin/mn_security_config.js'),
};

let otherSecuritySettingsState = {
  name: 'app.admin.security.other.**',
  url: '/other',
  lazyLoad: () => import('./mn.security.other.states.js'),
};

let auditState = {
  name: 'app.admin.security.audit.**',
  url: '/audit',
  lazyLoad: () => import('./mn.security.audit.states.js'),
};

router.stateRegistry.register(appState);
router.stateRegistry.register(adminState);
router.stateRegistry.register(authState);
router.stateRegistry.register(gsiState);
router.stateRegistry.register(wizardState);
router.stateRegistry.register(overviewState);
router.stateRegistry.register(securityState);
router.stateRegistry.register(otherSecuritySettingsState);
router.stateRegistry.register(auditState);

// TODO: Add auth state
// router.urlService.rules.initial({ state: 'app.auth' });

ReactDOM.render(
  <UIRouter router={router}>
    <div>
      <UIView />
    </div>
  </UIRouter>,
  document.getElementById('root')
);

// ReactDOM.render(
//   <MnAuthComponent />,
//   document.getElementById("root")
// );
