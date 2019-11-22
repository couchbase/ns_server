import angular from "/ui/web_modules/angular.js";
import ngMessages from "/ui/web_modules/angular-messages.js";
import uiRouter from "/ui/web_modules/@uirouter/angularjs.js";
import mnAuthService from "./mn_auth_service.js";
import mnAutocompleteOff from "/ui/app/components/directives/mn_autocomplete_off.js";
import mnFocus from "/ui/app/components/directives/mn_focus.js";

export default 'mnAuth';

angular
  .module('mnAuth', [mnAuthService, mnFocus, mnAutocompleteOff, ngMessages, uiRouter])
  .config(mnAuthConfig)
  .controller('mnAuthController', mnAuthController);

function mnAuthConfig($stateProvider, $httpProvider) {
  $httpProvider.interceptors.push(['$q', '$injector', interceptorOf401]);

  $stateProvider.state('app.auth', {
    url: "/auth",
    templateUrl: 'app/mn_auth/mn_auth.html',
    controller: 'mnAuthController as authCtl'
  });

  function interceptorOf401($q, $injector) {
    return {
      responseError: function (rejection) {
        if (rejection.status === 401 &&
            rejection.config.url !== "/pools" &&
            rejection.config.url !== "/controller/changePassword" &&
            rejection.config.url !== "/uilogout" &&
            ($injector.get('$state').includes('app.admin') ||
             $injector.get('$state').includes('app.wizard')) &&
            !rejection.config.headers["ignore-401"] &&
            !$injector.get('mnLostConnectionService').getState().isActive) {
          $injector.get('mnAuthService').logout();
        }
        return $q.reject(rejection);
      }
    };
  }
}

function mnAuthController(mnAuthService, $location, $state, $urlRouter) {
  var vm = this;

  vm.loginFailed = false;
  vm.submit = submit;

  activate();

  function activate() {
    if ($state.transition.$from().includes["app.wizard"]) {
      error({status: "initialized"})
    }

    mnAuthService.canUseCertForAuth().then(function (data) {
      vm.canUseCert = data.cert_for_auth;
    });
  }

  function error(resp) {
    vm.error = {};
    vm.error["_" + resp.status] = true;
  }
  function success() {
    /* never sync to /auth URL (as user will stay on the login page) */
    if ($location.path() === "/auth") {
      $state.go('app.admin.overview.statistics');
    } else {
      $urlRouter.sync();
    }
  }
  function submit(useCertForAuth) {
    mnAuthService
      .login(vm.user, useCertForAuth)
      .then(success, error);
  }
}
