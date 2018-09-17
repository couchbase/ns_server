var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnAdmin =
  (function (Rx) {
    "use strict";

    MnAdminComponent.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-admin.html",
        animations: [
          ng.animations.trigger(
            'mnMinimize', [
              ng.animations.state(
                ':enter',
                ng.animations.style({opacity: '0', height: '0'}),
                // ng.animations.animation('500ms',
                //                         ng.animations.style({opacity: '1', height: '2rem'}))
              ),
              ng.animations.state(
                ':leave',
                ng.animations.style({opacity: '1', height: '2rem'}),
                ng.animations.animation('500ms',
                                        ng.animations.style({opacity: '0', height: '0'}))
              )
            ]),
          ng.animations.trigger(
            'mnAnimateHeight', [

              ng.animations.transition(':enter', [
                ng.animations.style({opacity: 0, height: 0}),  // initial
                ng.animations.animate('0.4s ease',
                        ng.animations.style({opacity: 1, height: '*' }))  // final
              ]),

              ng.animations.transition(':leave', [
                ng.animations.style({opacity: 1, height: '*' }),
                ng.animations.animate('0.4s ease',
                        ng.animations.style({
                          opacity: 0,
                          height: '0px'
                        }))
              ])

            ]
          )
        ]
      })
    ];

    MnAdminComponent.parameters = [
      mn.services.MnAuth,
      mn.services.MnAdmin,
      mn.services.MnPools,
      mn.services.MnPermissions,
      mn.services.MnTasks,
      mn.services.MnAlerts,
      mn.services.MnSession,
      window['@uirouter/angular'].UIRouter
    ];

    MnAdminComponent.prototype.ngOnDestroy = ngOnDestroy;
    MnAdminComponent.prototype.onLogout = onLogout;
    MnAdminComponent.prototype.runInternalSettingsDialog = runInternalSettingsDialog;
    MnAdminComponent.prototype.showResetPasswordDialog = showResetPasswordDialog;
    MnAdminComponent.prototype.toggleProgressBar = toggleProgressBar;

    return MnAdminComponent;

    function MnAdminComponent(mnAuthService, mnAdminService,
                              mnPoolsService,
                              mnPermissionsService,
                              mnTasksService,
                              mnAlertsService,
                              mnSessionService,
                              uiRouter
                             ) {
      this.logoutHttp = mnAuthService.stream.logoutHttp;
      this.destroy = new Rx.Subject();
      this.isProgressBarClosed = new Rx.BehaviorSubject(true);
      this.mnAdminService = mnAdminService;
      this.showRespMenu = false;

      this.majorMinorVersion = mnPoolsService.stream.majorMinorVersion;
      this.tasksToDisplay = mnTasksService.stream.tasksToDisplay;
      this.isEnterprise = mnPoolsService.stream.isEnterprise;
      this.whomiId = mnAdminService.stream.whomi.pipe(
        Rx.operators.pluck("id")
      );

      this.mnAlerts = mnAlertsService.stream.alerts;


      mnSessionService.activate(this.destroy);

      this.tasksRead =
        mnPermissionsService.createPermissionStream("tasks!read");
      this.securityRead =
        mnPermissionsService.createPermissionStream("tasks!read");
      this.bucketSettingsAnyRead =
        mnPermissionsService.createPermissionStream("settings!read", ".");

      this.stateService = uiRouter.stateService;

      mnAdminService.stream.getPoolsDefault
        .pipe(
          Rx.operators.takeUntil(this.destroy)
        )
        .subscribe(function (rv) {
          mnAdminService.stream.etag.next(rv.etag);
        }, function (rv) {
          if ((rv instanceof ng.common.http.HttpErrorResponse) && (rv.status === 404)) {
            uiRouter.stateService.go('app.wizard.welcome', null, {location: false});
          }
        });

      this.isAdminRootReady =
        mnAdminService.stream.getPoolsDefault.pipe(
          Rx.operators.map(Boolean)
        );

      this.clusterName =
        mnAdminService.stream.getPoolsDefault.pipe(
          Rx.operators.pluck("clusterName")
        );

      this.enableResetButton =
        Rx.combineLatest(
          mnPoolsService.stream.isEnterprise,
          mnAdminService.stream.compatVersion.pipe(Rx.operators.pluck("atLeast50")),
          mnAdminService.stream.whomi.pipe(
            Rx.operators.map(function (my) {
              return my.domain === 'local' || my.domain === 'admin';
            })
          )
        ).pipe(
          Rx.operators.map(_.curry(_.every)(_, Boolean))
        );

      this.enableInternalSettings =
        Rx.combineLatest(
          mnAdminService.stream.enableInternalSettings,
          mnPermissionsService.createPermissionStream("admin.settings!write")
        ).pipe(
          Rx.operators.map(_.curry(_.every)(_, Boolean))
        );

      this.tasksRead
        .pipe(
          Rx.operators.switchMap(function (canRead) {
            return canRead ? mnTasksService.stream.extractNextInterval : Rx.NEVER;
          }),
          Rx.operators.takeUntil(this.destroy)
        )
        .subscribe(function (interval) {
          mnTasksService.stream.interval.next(interval);
        });
    }

    function ngOnDestroy() {
      this.destroy.next();
      this.destroy.complete();
      this.mnAdminService.stream.etag.next();
    }

    function onLogout() {
      this.logoutHttp.post(true);
    }

    function runInternalSettingsDialog() {

    }

    function showResetPasswordDialog() {

    }

    function toggleProgressBar() {
      this.isProgressBarClosed.next(!this.isProgressBarClosed.getValue());
    }
  })(window.rxjs);


var mn = mn || {};
mn.modules = mn.modules || {};
mn.modules.MnAdmin =
  (function () {
    "use strict";

    OverviewComponent.annotations = [
      new ng.core.Component({
        template: 'overview'
      })
    ];
    function OverviewComponent() {
    }

    ServersComponent.annotations = [
      new ng.core.Component({
        template: '<mn-element-cargo depot="alerts">asdasdasdas</mn-element-cargo>'
      })
    ];
    function ServersComponent() {
    }

    MnAdminModule.annotations = [
      new ng.core.NgModule({
        declarations: [
          mn.directives.MnDraggable,
          mn.components.MnAdmin,
          OverviewComponent,
          ServersComponent,
          mn.components.MnBuckets,
          mn.components.MnBucketsItem,
          mn.components.MnBucketsItemDetails,
          mn.components.MnBarUsage,
          mn.components.MnWarmupProgress,
          mn.components.MnBucketsDialog,
          mn.components.MnSessionTimeoutDialog,
          mn.components.MnAutocompactionForm
        ],
        imports: [
          window['@uirouter/angular'].UIRouterModule.forChild({
            states: [{
              name: "app.admin.overview",
              url: "overview",
              views: {
                "main@app.admin": OverviewComponent
              },
              data: {
                title: "Dashboard"
              }
            }, {
              name: "app.admin.servers",
              url: "servers",
              views: {
                "main@app.admin": ServersComponent
              },
              data: {
                title: "Servers"
              }
            }, {
              name: "app.admin.buckets",
              url: "buckets?openedBuckets",
              params: {
                openedBuckets: {
                  array: true,
                  dynamic: true
                }
              },
              views: {
                "main@app.admin": mn.components.MnBuckets
              },
              data: {
                title: "Buckets"
              }
            }, {
              name: "app.admin.security",
              url: "security",
              views: {
                "main@app.admin": mn.components.MnSecurity
              },
              data: {
                title: "Security"
              }
            }, {
              name: "app.admin.settings",
              url: "settings",
              views: {
                "main@app.admin": mn.components.MnSettings
              },
              data: {
                title: "Settingsy"
              }
            }]
          }),
          ng.forms.ReactiveFormsModule,
          mn.modules.MnShared,
          mn.modules.MnSecurity,
          mn.modules.MnSettings,
          mn.modules.MnElementModule,
          mn.modules.MnPipesModule,
          ng.platformBrowser.BrowserModule,
          ngb.NgbModule,
          ng.platformBrowser.animations.BrowserAnimationsModule
        ],
        providers: [
          mn.services.MnAdmin
        ],
        entryComponents: [
          mn.components.MnSessionTimeoutDialog,
          mn.components.MnBucketsDialog
        ]
      })
    ];

    return MnAdminModule;

    function MnAdminModule() {
    }
  })();
