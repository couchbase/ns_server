import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {pipe, BehaviorSubject} from '/ui/web_modules/rxjs.js';
import {withLatestFrom, map, filter, switchMap, pluck, shareReplay,
        takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {UIRouter} from '/ui/web_modules/@uirouter/angular.js';
import {FormBuilder} from '/ui/web_modules/@angular/forms.js';

import {MnAlertsService, $rootScope} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {MnFormService} from "./mn.form.service.js";
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnPoolsService} from "./mn.pools.service.js";
import {MnAdminService} from "./mn.admin.service.js";
import {MnBucketsService} from "./mn.buckets.service.js";

export {MnXDCRAddRepComponent};

class MnXDCRAddRepComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.xdcr.add.rep.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
    })
  ]}

  static get parameters() { return [
    MnFormService,
    MnPoolsService,
    MnXDCRService,
    MnBucketsService,
    MnAdminService,
    MnAlertsService,
    $rootScope,
    UIRouter,
    FormBuilder
  ]}

  constructor(mnFormService, mnPoolsService, mnXDCRService, mnBucketsService, mnAdminService,
              mnAlertsService, $rootScope, uiRouter, formBuilder) {
    super();

    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.bucketsMembaseEphemeral = mnBucketsService.stream.bucketsMembaseEphemeral;
    this.getSettingsReplications = mnXDCRService.stream.getSettingsReplications;
    this.remoteClusters = mnXDCRService.stream.getRemoteClustersFiltered;
    this.postCreateReplication = mnXDCRService.stream.postCreateReplication;
    this.postSettingsReplicationsValidation =
      mnXDCRService.stream.postSettingsReplicationsValidation;


    this.form = mnFormService.create(this)
      .setFormGroup({fromBucket: "",
                     toCluster: "",
                     toBucket: "",
                     priority: null,
                     filterExpression: "",
                     filterExpiration: false,
                     filterSkipRestream: "false",
                     filterDeletion: false,
                     filterBypassExpiry: false,
                     collectionsExplicitMapping: false,
                     collectionsMigrationMode: false,
                     compressionType: null,
                     sourceNozzlePerNode: null,
                     targetNozzlePerNode: null,
                     checkpointInterval: null,
                     workerBatchSize: null,
                     docBatchSizeKb: null,
                     failureRestartInterval: null,
                     optimisticReplicationThreshold: null,
                     statsInterval: null,
                     networkUsageLimit: null,
                     logLevel: null})
      .setPackPipe(pipe(withLatestFrom(this.isEnterprise,
                                       mnAdminService.stream.compatVersion55),
                        map(mnXDCRService.prepareReplicationSettigns.bind(this))))
      .setSource(this.getSettingsReplications)
      .setPostRequest(this.postCreateReplication)
      .setValidation(this.postSettingsReplicationsValidation)
      .clearErrors()
      .showGlobalSpinner()
      .success(data => {
        $rootScope.$broadcast("reloadTasksPoller");
        uiRouter.stateService.go('app.admin.replications').then(() => {
          var hasWarnings = !!(data.warnings && data.warnings.length);
          mnAlertsService.formatAndSetAlerts(
            hasWarnings ? resp.data.warnings : "Replication created successfully!",
            hasWarnings ? 'warning': "success",
            hasWarnings ? 0 : 2500);
        });
      });

    this.explicitMappingGroup = {
      scopes: {
        flags: formBuilder.group({}),
        fields: formBuilder.group({})
      },
      collections: {},
      collectionsControls: {},
      migrationMode: formBuilder.group({key: "", target: ""})
    };

    this.explicitMappingRules = new BehaviorSubject({});
    this.explicitMappingMigrationRules = new BehaviorSubject({});

  }
}
