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

let ajsUpgradedProviders = [
  $stateProvider,
  MnPendingQueryKeeper
];

export {
  ajsUpgradedProviders,
  $state,
  MnPendingQueryKeeper
};
