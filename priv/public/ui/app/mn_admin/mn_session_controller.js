import angular from "/ui/web_modules/angular.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnSessionService from "/ui/app/components/mn_session.js";

export default 'mnSession';

angular
  .module('mnSession', [mnSessionService, mnPromiseHelper])
  .controller('mnSessionController', mnSessionController);

function mnSessionController(mnSessionService, mnPromiseHelper) {
  var vm = this;

  vm.submit = submit;

  activate();

  function activate() {
    mnPromiseHelper(vm, mnSessionService.get())
      .applyToScope("state");
  }

  function submit() {
    if (vm.viewLoading) {
      return;
    }
    mnPromiseHelper(vm, mnSessionService.post(vm.state.uiSessionTimeout))
      .catchErrors()
      .showSpinner()
      .showGlobalSuccess("Session settings changed successfully!");
  };
}
