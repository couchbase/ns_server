import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {NgbActiveModal} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {pipe, Subject} from '/ui/web_modules/rxjs.js';
import {withLatestFrom, map, filter, switchMap, pluck,
        takeUntil} from '/ui/web_modules/rxjs/operators.js';

import {MnAlertsService, $rootScope} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from "./mn.core.js";
import {MnFormService} from "./mn.form.service.js";
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnPoolsService} from "./mn.pools.service.js";
import {MnAdminService} from "./mn.admin.service.js";
import {MnBucketsService} from "./mn.buckets.service.js";

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
    NgbActiveModal,
    $rootScope,
    MnCollectionsService
  ]}

  constructor(mnFormService, mnPoolsService, mnXDCRService, mnBucketsService, mnAdminService, mnAlertsService, activeModal, $rootScope, mnCollectionsService) {
    super();

    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.activeModal = activeModal;
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
        activeModal.close();
        $rootScope.$broadcast("reloadTasksPoller");
        var hasWarnings = !!(data.warnings && data.warnings.length);
        mnAlertsService.formatAndSetAlerts(
          hasWarnings ? resp.data.warnings : "Replication created successfully!",
          hasWarnings ? 'warning': "success",
          hasWarnings ? 0 : 2500);
      });

    this.explicitMappingForm = mnFormService.create(this)
      .setFormGroup({scope: "",
                     collection: "",
                     key: "",
                     target: ""});

    this.selectedBucketScopes =
      this.form.group.get("fromBucket").valueChanges
      .pipe(filter(v => !!v),
            switchMap(bucketName => mnCollectionsService.getManifest(bucketName)),
            pluck("scopes"));



    var explicitMappingRules = {};
    var explicitRuleBasedMappings = {};

    var addExplicitMappingRules = new Subject();
    var addExplicitRuleBasedMappings = new Subject();

    this.explicitMappingRules = explicitMappingRules;
    this.explicitRuleBasedMappings = explicitRuleBasedMappings;

    this.addExplicitMappingRules = addExplicitMappingRules;
    this.addExplicitRuleBasedMappings = addExplicitRuleBasedMappings;

    this.delExplicitMappingRules = delExplicitMappingRules;
    this.delExplicitRuleBasedMappings = delExplicitRuleBasedMappings;

    this.getExplicitMappingRulesKeys = getExplicitMappingRulesKeys
    this.getExplicitRuleBasedMappingsKeys = getExplicitRuleBasedMappingsKeys;

    addExplicitMappingRules
      .pipe(filter(() => !!this.explicitMappingForm.group.value.scope),
            map(() => getExplicitMappingRules(this.explicitMappingForm.group.value)),
            takeUntil(this.mnOnDestroy))
      .subscribe(v => {
        explicitMappingRules[v[0]] = v[1];
        resetExplicitMappingForm.bind(this)();
      });

    addExplicitRuleBasedMappings
      .pipe(filter(() => !!this.explicitMappingForm.group.value.key),
            map(() => [this.explicitMappingForm.group.value.key,
                       this.explicitMappingForm.group.value.target]),
            takeUntil(this.mnOnDestroy))
      .subscribe(v => {
        explicitRuleBasedMappings[v[0]] = v[1];
        resetExplicitMappingForm.bind(this)();
      });

    function getExplicitMappingRulesKeys() {
      return Object.keys(explicitMappingRules);
    }
    function getExplicitRuleBasedMappingsKeys() {
      return Object.keys(explicitRuleBasedMappings);
    }
    function delExplicitMappingRules(key) {
      delete explicitMappingRules[key];
    }
    function delExplicitRuleBasedMappings(key) {
      delete explicitRuleBasedMappings[key];
    }
    function getExplicitMappingRules(values) {
      var key = values.scope.name +
          (values.collection.name ? (":" + values.collection.name) : "");
      var value = values.target || null;
      return [key, value];
    }
    function resetExplicitMappingForm() {
      this.explicitMappingForm.group.patchValue({
        scope: "",
        collection: "",
        target: "",
        key: ""
      });
    }

  }
}
