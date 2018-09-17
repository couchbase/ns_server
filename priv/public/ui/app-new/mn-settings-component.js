var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnSettings =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnSettings, mn.helper.MnEventableComponent);

    MnSettings.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-settings.html"
      })
    ];

    MnSettings.parameters = [
      mn.services.MnPermissions,
      mn.services.MnPools,
      mn.services.MnAdmin
    ];

    return MnSettings;

    function MnSettings(mnPermissionsService, mnPoolsService, mnAdminService) {
      mn.helper.MnEventableComponent.call(this);

      this.settingsRead = mnPermissionsService.createPermissionStream("admin.settings!read");
      this.isEnterprise = mnPoolsService.stream.isEnterprise;
    }

  })(window.rxjs);


var mn = mn || {};
mn.modules = mn.modules || {};
mn.modules.MnSettings =
  (function () {
    "use strict";

    MnSettingsModule.annotations = [
      new ng.core.NgModule({
        declarations: [
          mn.components.MnSettings,
          mn.components.MnEmailAlerts
        ],
        imports: [
          window['@uirouter/angular'].UIRouterModule.forChild({
            states: [
              {
                name: 'app.admin.settings.emailAlerts',
                url: '/alerts',
                component: mn.components.MnEmailAlerts
                // data: {
                //   permissions: 'cluster.settings.read'
                // }
              },

              // {
              //   name: "app.admin.security.session",
              //   url: '/session',
              //   component: mn.components.MnSession,
              //   // data: {
              //   //   permissions: "cluster.admin.security.read"
              //   // }
              // }
            ]
          }),
          ng.forms.ReactiveFormsModule,
          mn.modules.MnShared,
          mn.modules.MnElementModule,
          mn.modules.MnPipesModule,
          ng.platformBrowser.BrowserModule,
          ngb.NgbModule,
          // ng.platformBrowser.animations.BrowserAnimationsModule
        ],
        providers: [
          mn.services.MnSettings
        ],
        entryComponents: [
          // mn.components.MnBucketsDialog
        ]
      })
    ];

    return MnSettingsModule;

    function MnSettingsModule() {
    }
  })();
