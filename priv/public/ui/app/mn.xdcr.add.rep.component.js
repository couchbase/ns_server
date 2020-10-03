import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {pipe, Subject} from '/ui/web_modules/rxjs.js';
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
import {MnHelperService} from './mn.helper.service.js';

import {MnCollectionsService} from './mn.collections.service.js';

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
    MnHelperService,
    $rootScope,
    MnCollectionsService,
    UIRouter,
    FormBuilder
  ]}

  constructor(mnFormService, mnPoolsService, mnXDCRService, mnBucketsService, mnAdminService, mnAlertsService, mnHelperService, $rootScope, mnCollectionsService, uiRouter, formBuilder) {
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
                     type: "xmem",
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

    this.form.group.get("collectionsExplicitMapping").valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(enabled => {
        if (enabled) {
          this.form.group.get("collectionsMigrationMode").patchValue(false, {onlySelf: true});
        }
      });

    this.form.group.get("collectionsMigrationMode").valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(enabled => {
        if (enabled) {
          this.form.group.get("collectionsExplicitMapping").patchValue(false, {onlySelf: true});
        }
      });

    this.form.group.valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(group => {
        let action = !!group.fromBucket ? "enable" : "disable";
        this.form.group.get("collectionsExplicitMapping")[action]({onlySelf: true});
        this.form.group.get("collectionsMigrationMode")[action]({onlySelf: true});
      });

    this.scopesFilter = mnHelperService.createFilter("name");

    this.scopes =
      this.form.group.get("fromBucket").valueChanges
      .pipe(filter(v => !!v),
            switchMap(bucketName => mnCollectionsService.getManifest(bucketName)),
            pluck("scopes"),
            this.scopesFilter.pipe,
            shareReplay({refCount: true, bufferSize: 1}));

    this.scopesPaginator =
      mnHelperService.createPagenator(this, this.scopes, "scopesPage");

    this.explicitRuleBasedMappingGroup = formBuilder.group({
      migrationKey: "",
      migrationTarget: ""
    });

    this.explicitMappingGroup = {
      scopes: {
        flags: formBuilder.group({}),
        fields: formBuilder.group({})
      },
      collections: {},
      collectionsControls: {}
    };

    var explicitMappingRules = {};
    var explicitRuleBasedMappings = {};

    var addExplicitRuleBasedMappings = new Subject();

    this.explicitMappingRules = explicitMappingRules;
    this.explicitRuleBasedMappings = explicitRuleBasedMappings;

    this.addExplicitRuleBasedMappings = addExplicitRuleBasedMappings;

    this.delExplicitMappingRules = delExplicitMappingRules;
    this.delExplicitRuleBasedMappings = delExplicitRuleBasedMappings;

    this.getExplicitMappingRulesKeys = getExplicitMappingRulesKeys
    this.getExplicitRuleBasedMappingsKeys = getExplicitRuleBasedMappingsKeys;

    addExplicitRuleBasedMappings
      .pipe(filter(() => !!this.explicitRuleBasedMappingGroup.value.migrationKey),
            map(() => [this.explicitRuleBasedMappingGroup.value.migrationKey,
                       this.explicitRuleBasedMappingGroup.value.migrationTarget]),
            takeUntil(this.mnOnDestroy))
      .subscribe(v => {
        explicitRuleBasedMappings[v[0]] = v[1];
        resetExplicitRuleBasedMappingGroup.bind(this)();
      });

    function getExplicitMappingRulesKeys() {
      return Object.keys(explicitMappingRules);
    }
    function getExplicitRuleBasedMappingsKeys() {
      return Object.keys(explicitRuleBasedMappings);
    }
    function delExplicitMappingRules(key) {
      let scopeCollection = key.split(":");
      if (scopeCollection.length == 2) {
        this.explicitMappingGroup
          .collections[scopeCollection[0]]
          .flags.get(scopeCollection[1]).setValue(explicitMappingRules[key] == null);
      } else {
        this.explicitMappingGroup
          .scopes.flags.get(scopeCollection[0]).setValue(false);
        Object.keys(explicitMappingRules).forEach(mapKey => {
          if (mapKey.startsWith(scopeCollection[0])) {
            delete explicitMappingRules[mapKey];
          }
        });
      }
      delete explicitMappingRules[key];
    }
    function delExplicitRuleBasedMappings(key) {
      delete explicitRuleBasedMappings[key];
    }
    function resetExplicitMappingGroup() {
      this.explicitMappingGroup.patchValue({scope: "", targetScope: ""});
    }
    function resetExplicitRuleBasedMappingGroup() {
      this.explicitRuleBasedMappingGroup.patchValue({migrationKey: "", migrationTarget: ""});
    }

  }
}
