var mn = mn || {};
mn.modules = mn.modules || {};
mn.modules.MnWizard =
  (function (Rx) {
    "use strict";

    MnWizardComponent.annotations = [
      new ng.core.Component({
        templateUrl: 'app-new/mn-wizard.html'
      })
    ];

    MnWizardComponent.parameters = [
      mn.services.MnWizard,
      mn.services.MnPools,
      mn.services.MnAdmin
    ];

    function MnWizardComponent(mnWizardService, mnPoolsService, mnAdminService) {
      var newClusterConfig = mnWizardService.wizardForm.newClusterConfig;
      var joinCluster = mnWizardService.wizardForm.joinCluster;

      mnAdminService.stream.implementationVersion.pipe(
        Rx.operators.first()
      ).subscribe(function (implementationVersion) {
        mnWizardService.initialValues.implementationVersion = implementationVersion;
      });

      mnWizardService.stream.getSelfConfig.pipe(
        Rx.operators.first()
      ).subscribe(function (selfConfig) {
        var hostname = selfConfig['otpNode'].split('@')[1] || '127.0.0.1';
        newClusterConfig.get("clusterStorage.hostname").setValue(hostname);
        newClusterConfig.get("services.field.kv").setValue(selfConfig.memoryQuota);
        newClusterConfig.get("services.field.index").setValue(selfConfig.indexMemoryQuota);
        newClusterConfig.get("services.field.fts").setValue(selfConfig.ftsMemoryQuota);
        newClusterConfig.get("services.field.cbas").setValue(selfConfig.cbasMemoryQuota);
        newClusterConfig.get("services.field.eventing").setValue(selfConfig.eventingMemoryQuota);
        joinCluster.get("clusterStorage.hostname").setValue(hostname);

        mnWizardService.initialValues.hostname = hostname;
      });

      mnPoolsService.stream.isEnterprise
        .subscribe(function (isEnterprise) {
          var storageMode = isEnterprise ? "plasma" : "forestdb";
          newClusterConfig.get("storageMode").setValue(storageMode);

          if (!isEnterprise) {
            (["cbas", "eventing"]).forEach(function (service) {
              newClusterConfig.get("services.flag." + service).setValue(false);
              newClusterConfig.get("services.flag." + service).disable({onlySelf: true});
              newClusterConfig.get("services.field." + service).setValue(null);
              newClusterConfig.get("services.field." + service).disable({onlySelf: true});
              joinCluster.get("services.flag." + service).setValue(false);
              joinCluster.get("services.flag." + service).disable({onlySelf: true});
              joinCluster.get("clusterStorage.storage.cbas_path").disable({onlySelf: true});
              newClusterConfig.get("clusterStorage.storage.cbas_path").disable({onlySelf: true});
            });
          }

          mnWizardService.initialValues.storageMode = storageMode;
        });

      mnWizardService.stream.initHddStorage.pipe(
        Rx.operators.first()
      ).subscribe(function (initHdd) {
        newClusterConfig.get("clusterStorage.storage").patchValue(initHdd);
        joinCluster.get("clusterStorage.storage").patchValue(initHdd);

        mnWizardService.initialValues.clusterStorage = initHdd;
      });
    }

    MnWizardModule.annotations = [
      new ng.core.NgModule({
        declarations: [
          MnWizardComponent,
          mn.components.MnNewCluster,
          mn.components.MnNewClusterConfig,
          mn.components.MnTermsAndConditions,
          mn.components.MnWelcome,
          mn.components.MnNodeStorageConfig,
          mn.components.MnQuerySettingsConfig,
          mn.components.MnServicesConfig,
          mn.components.MnStorageMode,
          mn.components.MnJoinCluster,
          mn.components.MnPathField
        ],
        imports: [
          ng.platformBrowser.BrowserModule,
          ng.forms.ReactiveFormsModule,
          mn.modules.MnShared,
          mn.modules.MnPipesModule,
          ng.common.http.HttpClientJsonpModule,
          window['@uirouter/angular'].UIRouterModule.forChild({
            states: [{
              name: "app.wizard",
              component: MnWizardComponent,
              abstract: true
            }, {
              name: "app.wizard.welcome",
              component: mn.components.MnWelcome
            }, {
              name: "app.wizard.newCluster",
              component: mn.components.MnNewCluster
            }, {
              name: "app.wizard.joinCluster",
              component: mn.components.MnJoinCluster
            }, {
              name: "app.wizard.termsAndConditions",
              component: mn.components.MnTermsAndConditions
            }, {
              name: "app.wizard.newClusterConfig",
              component: mn.components.MnNewClusterConfig
            }]
          })
        ],
        providers: [
          mn.services.MnWizard
        ]
      })
    ];

    return MnWizardModule;

    function MnWizardModule() {
    }
  })(window.rxjs);
