var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnRootCertificate =
  (function () {
    "use strict";

    mn.helper.extends(MnRootCertificate, mn.helper.MnEventableComponent);

    MnRootCertificate.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-root-certificate.html"
      })
    ];

    MnRootCertificate.parameters = [

    ];

    return MnRootCertificate;

    function MnRootCertificate() {
      mn.helper.MnEventableComponent.call(this);
    }

  })();
