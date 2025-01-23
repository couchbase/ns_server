
import React from "react";
import ReactDOM from "react-dom";
import { UIRouter, UIView } from "@uirouter/react";
import { UIRouter as router }  from "mn.react.router";
import adminState from "./mn_admin/mn_admin_config.js";
import appState from "./app_config";


const authState = {
  name: "app.auth.**",
  url: '/auth',
  lazyLoad: () => import('./mn.auth.states')
};

const gsiState = {
  name: "app.admin.gsi.**",
  url: "/index",
  lazyLoad: () =>  import('./mn_admin/mn_gsi_states')
};

const wizardState = {
  name: 'app.wizard.**',
  lazyLoad: () =>  import('./mn.wizard.states')
};

const overviewState = {
  name: 'app.admin.overview.**',
  url: '/overview',
  lazyLoad: () =>  import('./mn_admin/mn_overview_states.js')
};

router.stateRegistry.register(appState);
router.stateRegistry.register(adminState);
router.stateRegistry.register(authState);
router.stateRegistry.register(gsiState);
router.stateRegistry.register(wizardState);
router.stateRegistry.register(overviewState);

// TODO: Add auth state
// router.urlService.rules.initial({ state: 'app.auth' });


ReactDOM.render(
  <UIRouter router={router}>
    <div>
      <UIView />
    </div>
  </UIRouter>,
  document.getElementById("root")
);

// ReactDOM.render(
//   <MnAuthComponent />,
//   document.getElementById("root")
// );

