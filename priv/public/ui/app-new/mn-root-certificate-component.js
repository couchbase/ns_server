var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnRootCertificate =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnRootCertificate, mn.helper.MnEventableComponent);

    MnRootCertificate.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-root-certificate.html",
        changeDetection: ng.core.ChangeDetectionStrategy.OnPush
      })
    ];

    MnRootCertificate.parameters = [
      mn.services.MnSecurity
    ];

    MnRootCertificate.prototype.setCertPem = setCertPem;

    return MnRootCertificate;

    function MnRootCertificate(mnSecurityService) {
      mn.helper.MnEventableComponent.call(this);

      var getDefaultCertificate = mnSecurityService.stream.getDefaultCertificate;
      var cert = getDefaultCertificate.pipe(Rx.operators.pluck("cert"));

      this.formGroup = new ng.forms.FormGroup({
        pem: new ng.forms.FormControl(null)
      });

      this.certType = cert.pipe(Rx.operators.map(function (cert) {
        return cert.type === "generated" ? "self-signed" : "signed";
      }));

      this.certSubject = cert.pipe(Rx.operators.pluck("subject"));
      this.certExpires = cert.pipe(Rx.operators.pluck("expires"));
      this.certWarnings = getDefaultCertificate.pipe(Rx.operators.pluck("warnings"));
      cert.pipe(Rx.operators.first()).subscribe(this.setCertPem.bind(this));
    }

    function setCertPem(cert) {
      this.formGroup.patchValue(cert);
    }

  })(window.rxjs);
