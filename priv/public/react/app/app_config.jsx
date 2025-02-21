import axios from 'axios';
import { UIView } from '@uirouter/react';
import { MnElementCraneProvider } from './mn.element.crane';
import { MnLifeCycleHooksToStream } from './mn.core';
import { MnHelperReactService } from './mn.helper.react.service';
import { UIRouter } from './mn.react.router';
import mnPools from 'components/mn_pools';
import mnPoolDefault from 'components/mn_pool_default';
import mnPermissions from 'components/mn_permissions';
import mnPendingQueryKeeper from 'components/mn_pending_query_keeper';

axios.defaults.headers.common['invalid-auth-response'] = 'on';
axios.defaults.headers.common['Cache-Control'] = 'no-cache';
axios.defaults.headers.common['Pragma'] = 'no-cache';
axios.defaults.headers.common['ns-server-ui'] = 'yes';

class AppComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.state = {
      mnGlobalSpinnerFlag: false,
    };
  }

  componentDidMount() {
    this.mnGlobalSpinnerFlag = MnHelperReactService.mnGlobalSpinnerFlag;
    MnHelperReactService.async(this, 'mnGlobalSpinnerFlag');
  }

  render() {
    const vm = this;
    const { mnGlobalSpinnerFlag } = vm.state;

    return (
      <>
        <div className="root-container">
          <MnElementCraneProvider>
            <UIView />
          </MnElementCraneProvider>
        </div>
        {mnGlobalSpinnerFlag && <div className="global-spinner"></div>}
      </>
    );
  }
}

UIRouter.urlService.rules.otherwise({ state: 'app.admin.overview.statistics' });

const appState = {
  name: 'app',
  url: '?{enableInternalSettings:bool}&{disablePoorMansAlerts:bool}&{enableDeveloperSettings:bool}',
  params: {
    enableDeveloperSettings: {
      value: null,
      squash: true,
    },
    enableInternalSettings: {
      value: null,
      squash: true,
    },
    disablePoorMansAlerts: {
      value: null,
      squash: true,
    },
  },
  abstract: true,
  // TODO: get back to this
  // resolve: {
  //   env: ['mnEnv', '$rootScope', function (mnEnv, $rootScope) {
  //     return mnEnv.loadEnv().then(function(env) {
  //       $rootScope.ENV = env;
  //     });
  //   }]
  // },
  // template: '<div ui-view="" class="root-container"></div>' +
  //   '<div ng-show="mnGlobalSpinnerFlag" class="global-spinner"></div>'
  component: AppComponent,
};

UIRouter.transitionService.onBefore(
  {
    to: (state) => state.data && state.data.requiresAuth,
  },
  (transition) => {
    let stateService = transition.router.stateService;
    let locationService = transition.router.locationService;

    return mnPools.get().then(
      (pools) => {
        if (!pools.isInitialized) {
          return stateService.target('app.wizard.welcome', null, {
            location: false,
          });
        } else {
          return true;
        }
      },
      function (resp) {
        switch (resp.status) {
          case 401:
            return stateService.target('app.auth', locationService.search(), {
              location: false,
            });
        }
      }
    );
  }
);

function isThisTransitionBetweenTabs(trans) {
  let toName = trans.to().name;
  let fromName = trans.from().name;
  return toName.indexOf(fromName) === -1 && fromName.indexOf(toName) === -1;
}

// TODO: get back to this
// UIRouter.transitionService.onFinish({
//   from: "app.admin.**",
//   to: "app.admin.**"
// }, function (trans) {
//   if (isThisTransitionBetweenTabs(trans)) {
//     mnHelper.mainSpinnerCounter.decrease();
//   }
// });

// TODO: review this errors happens during transaction to app.admin.gsi from overview
// UIRouter.transitionService.onError({
//   from: "app.admin.**",
//   to: "app.admin.**"
// }, function (trans) {
//   if (isThisTransitionBetweenTabs(trans)) {
//     mnHelper.mainSpinnerCounter.decrease();
//   }
// });

UIRouter.transitionService.onBefore(
  {
    from: 'app.admin.**',
    to: 'app.admin.**',
  },
  function (trans) {
    const dialogElement = document.querySelector('[role="dialog"]');
    const isModalOpen = !!dialogElement;

    if (MnHelperReactService.mnGlobalSpinnerFlag.getValue()) {
      return false;
    }
    if (!isModalOpen && isThisTransitionBetweenTabs(trans)) {
      //cancel tabs specific queries in case toName is not child of fromName and vise versa
      mnPendingQueryKeeper.cancelTabsSpecificQueries();
      // TODO: get back to this
      // mnHelper.mainSpinnerCounter.increase();
    }
    return !isModalOpen;
  }
);

UIRouter.transitionService.onBefore(
  {
    from: 'app.auth',
    to: 'app.admin.**',
  },
  function (trans) {
    return mnPools.get().then(
      function (pools) {
        return pools.isInitialized
          ? true
          : trans.router.stateService.target('app.wizard.welcome');
      },
      function (resp) {
        switch (resp.status) {
          case 401:
            return false;
        }
      }
    );
  }
);

UIRouter.transitionService.onBefore(
  {
    from: 'app.wizard.**',
    to: 'app.admin.**',
  },
  function () {
    return mnPools.getFresh().then(function (pools) {
      return pools.isInitialized;
    });
  }
);

UIRouter.transitionService.onBefore(
  {
    from: 'app.admin.cbas|query.**',
    to: 'app.admin.**',
  },
  function () {
    mnPoolDefault.setHideNavSidebar(false);
  }
);

UIRouter.transitionService.onStart(
  {
    to: function (state) {
      return state.data && state.data.permissions;
    },
  },
  function (trans) {
    return mnPermissions.check().then(function () {
      if (trans.to().data.permissions(mnPermissions.export.getValue())) {
        return true;
      } else {
        return trans.router.stateService.target(
          'app.admin.overview.statistics'
        );
      }
    });
  }
);

UIRouter.transitionService.onStart(
  {
    to: function (state) {
      return state.data && state.data.compat;
    },
  },
  function (trans) {
    return mnPoolDefault.get().then(function () {
      if (trans.to().data.compat(mnPoolDefault.export.getValue())) {
        return true;
      } else {
        return trans.router.stateService.target(
          'app.admin.overview.statistics'
        );
      }
    });
  }
);

UIRouter.transitionService.onStart(
  {
    to: function (state) {
      return state.data && state.data.enterprise;
    },
  },
  function (trans) {
    return mnPools.get().then(function (pools) {
      if (pools.isEnterprise) {
        return true;
      } else {
        return trans.router.stateService.target(
          'app.admin.overview.statistics'
        );
      }
    });
  }
);

export default appState;
