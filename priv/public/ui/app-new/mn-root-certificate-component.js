var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnRootCertificate =
  (function (Rx) {
    "use strict";

    MnRootCertificate.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-root-certificate.html",
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnRootCertificate.parameters = [
      mn.services.MnSecurity,
      mn.services.MnForm
    ];

    return MnRootCertificate;

    function MnRootCertificate(mnSecurityService, mnFormService) {

      this.cert = mnSecurityService.stream.getCertificate;

      this.form = mnFormService.create()
        .setFormGroup({pem: ""})
        .setSource(this.cert.pipe(Rx.operators.pluck("cert")));
    }

  })(window.rxjs);
