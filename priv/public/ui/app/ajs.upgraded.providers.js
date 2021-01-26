class $rootScope {}
const $rootScopeProvider = {
  provide: $rootScope,
  useFactory: function $rootScopeFactory(i) {
    return i.get('$rootScope');
  },
  deps: ['$injector']
};

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

class MnPoolDefault {}
const MnPoolDefaultProvider = {
  provide: MnPoolDefault,
  useFactory: function MnPoolDefaultFactory(i) {
    return i.get('mnPoolDefault');
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

class MnAuthService {}
const MnAuthServiceProvider = {
  provide: MnAuthService,
  useFactory: function MnPoolsFactory(i) {
    return i.get('mnAuthService');
  },
  deps: ['$injector']
};

class MnAlertsService {}
const MnAlertsServiceProvider = {
  provide: MnAlertsService,
  useFactory: function MnPoolsFactory(i) {
    return i.get('mnAlertsService');
  },
  deps: ['$injector']
};

class MnServersService {};
const MnServersServiceProvider = {
  provide: MnServersService,
  useFactory: function MnServersServiceFactory(i) {
    return i.get('mnServersService');
  },
  deps: ['$injector']
};

class MnStatisticsNewService {};
const MnStatisticsNewServiceProvider = {
  provide: MnStatisticsNewService,
  useFactory: function MnStatisticsNewServiceFactory(i) {
    return i.get('mnStatisticsNewService');
  },
  deps: ['$injector']
};

let ajsUpgradedProviders = [
  $rootScopeProvider,
  $stateProvider,
  MnPoolsProvider,
  MnPendingQueryKeeperProvider,
  MnPermissionsProvider,
  MnAuthServiceProvider,
  MnAlertsServiceProvider,
  MnServersServiceProvider,
  MnStatisticsNewServiceProvider,
  MnPoolDefaultProvider
];

export {
  ajsUpgradedProviders,
  $state,
  $rootScope,
  MnPools,
  MnPendingQueryKeeper,
  MnPermissions,
  MnAuthService,
  MnAlertsService,
  MnServersService,
  MnStatisticsNewService,
  MnPoolDefault
};
