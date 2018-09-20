var mn = mn || {};
mn.modules = mn.modules || {};
mn.modules.MnShared =
  (function () {
    "use strict";

    MnSharedModule.annotations = [
      new ng.core.NgModule({
        declarations: [
          mn.directives.MnFocus,
          mn.components.MnAutoCompactionForm,
          mn.components.MnPeriod
        ],
        exports: [
          mn.directives.MnFocus,
          mn.components.MnAutoCompactionForm
        ],
        imports: [
          ng.forms.ReactiveFormsModule,
          ng.platformBrowser.BrowserModule,
          ngb.NgbModule,
        ]
      })
    ];

    return MnSharedModule;

    function MnSharedModule() {
    }
  })();
