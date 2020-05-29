class $state {}
const $stateProvider = {
  provide: $state,
  useFactory: function $stateFactory(i) {
    return i.get('$state');
  },
  deps: ['$injector']
};

class MnPendingQueryKeeper {}
const MnPendingQueryKeeperProvider = {
  provide: MnPendingQueryKeeper,
  useFactory: function MnPendingQueryKeeperFactory(i) {
    return i.get('mnPendingQueryKeeper');
  },
  deps: ['$injector']
};

class MnPools {}
const MnPoolsProvider = {
  provide: MnPools,
  useFactory: function MnPoolsFactory(i) {
    return i.get('mnPools');
  },
  deps: ['$injector']
};

class MnPermissions {}
const MnPermissionsProvider = {
  provide: MnPermissions,
  useFactory: function MnPermissionsFactory(i) {
    return i.get('mnPermissions');
  },
  deps: ['$injector']
};


let ajsUpgradedProviders = [
  $stateProvider,
  MnPoolsProvider,
  MnPendingQueryKeeperProvider,
  MnPermissionsProvider
];

export {
  ajsUpgradedProviders,
  $state,
  MnPools,
  MnPendingQueryKeeper,
  MnPermissions
};
