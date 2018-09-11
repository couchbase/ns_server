var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnSessionTimeoutDialog =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnSessionTimeoutDialog, mn.helper.MnEventableComponent);

    MnSessionTimeoutDialog.annotations = [
      new ng.core.Component({
        selector: "mn-session-timeout-dialog-component",
        templateUrl: "app-new/mn-session-timeout-dialog.html",
      })
    ];

    MnSessionTimeoutDialog.parameters = [
      ngb.NgbActiveModal
    ];

    return MnSessionTimeoutDialog;

    function MnSessionTimeoutDialog(activeModal) {
      mn.helper.MnEventableComponent.call(this);
      this.activeModal = activeModal;

      var time = (Number(localStorage.getItem("uiSessionTimeout")) - 30000) / 1000;

      this.formGroup = new ng.forms.FormGroup({});

      this.time =
        Rx.interval(1000)
        .pipe(
          Rx.operators.scan(function(acc) {
            return --acc;
          }, time),
          Rx.operators.startWith(time));
    }
  })(window.rxjs);
