import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {combineLatest, pipe, BehaviorSubject} from '/ui/web_modules/rxjs.js';
import {map, withLatestFrom, takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {UIRouter} from "/ui/web_modules/@uirouter/angular.js";
import {FormBuilder} from '/ui/web_modules/@angular/forms.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnFormService} from "./mn.form.service.js";
import {MnPoolsService} from "./mn.pools.service.js";
import {MnAdminService} from "./mn.admin.service.js";

export {MnXDCREditRepComponent};

class MnXDCREditRepComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.xdcr.edit.rep.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item"
      ]
    })
  ]}

  static get parameters() { return [
    MnXDCRService,
    MnFormService,
    MnPoolsService,
    MnAdminService,
    UIRouter,
    FormBuilder
  ]}

  constructor(mnXDCRService, mnFormService, mnPoolsService, mnAdminService, uiRouter,
              formBuilder) {
    super();
    this.item = uiRouter.globals.params.item;
    this.uiRouter = uiRouter;
    this.isEditMode = true;
    this.formBuilder = formBuilder;
    this.mnFormService = mnFormService;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.compatVersion55 = mnAdminService.stream.compatVersion55;
    this.prepareReplicationSettigns = mnXDCRService.prepareReplicationSettigns.bind(this);
    this.getSettingsReplications = mnXDCRService.stream.getSettingsReplications
    this.postSettingsReplicationsValidation =
      mnXDCRService.stream.postSettingsReplicationsValidation;
    this.postSettingsReplications =
      mnXDCRService.stream.postSettingsReplications;
    this.createGetSettingsReplicationsPipe =
      mnXDCRService.createGetSettingsReplicationsPipe.bind(mnXDCRService);
  }

  ngOnInit() {
    this.replicationSettings =
      combineLatest(this.getSettingsReplications,
                    this.createGetSettingsReplicationsPipe(this.item.id));

    this.form = this.mnFormService.create(this)
      .setFormGroup({type: null,
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
      .setPackPipe(pipe(
        withLatestFrom(this.isEnterprise, this.compatVersion55),
        map(this.prepareReplicationSettigns),
        map(data => [this.item.id, data])))
      .setUnpackPipe(map(function (source) {
        if (source[1].collectionsMigrationMode) {
          source[1].collectionsExplicitMapping = false;
        }
        return Object.assign({}, source[0], source[1]);
      }))
      .setSource(this.replicationSettings)
      .setPostRequest(this.postSettingsReplications)
      .setValidation(this.postSettingsReplicationsValidation)
      .successMessage("Settings saved successfully!")
      .clearErrors()
      .success(() => this.uiRouter.stateService.go('app.admin.replications'));

    this.replicationSettings
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.unpackReplicationSettings.bind(this));
  }

  unpackReplicationSettings(v) {
    let scopesFlags = {};
    let scopesFields = {};
    let collections = {};
    let collectionsControls = {};

    Object.keys(v[1].colMappingRules).forEach(sourceRule => {
      let targetRule = v[1].colMappingRules[sourceRule];
      let sourcePair = sourceRule.split(":");

      scopesFlags[sourcePair[0]] = true;

      if (sourcePair.length == 2) {
        if (!collections[sourcePair[0]]) {
          collections[sourcePair[0]] = {
            flags: this.formBuilder.group({}),
            fields: this.formBuilder.group({})
          };
        }

        let collectionFlag = collections[sourcePair[0]].flags.get(sourcePair[1]);
        let collectionField = collections[sourcePair[0]].fields.get(sourcePair[1]);
        let fieldValue = targetRule ? targetRule.split(":")[1] : sourcePair[1];

        if (collectionFlag) {
          collectionFlag.setValue(!!targetRule, {emitEvent: false});
          collectionField.setValue(fieldValue, {emitEvent: false});
        } else {
          collections[sourcePair[0]]
            .flags.addControl(sourcePair[1], this.formBuilder.control(!!targetRule));
          collections[sourcePair[0]]
            .fields.addControl(sourcePair[1], this.formBuilder.control(fieldValue));
        }

        if (!collectionsControls[sourcePair[0]]) {
          collectionsControls[sourcePair[0]] = this.formBuilder.group({
            checkAll: this.formBuilder.control(true),
            denyMode: this.formBuilder.control(false)
          });
        }

        if (targetRule) {
          scopesFields[sourcePair[0]] = targetRule.split(":")[0];
        } else {
          collectionsControls[sourcePair[0]].get("denyMode").setValue(true);
        }
      } else {
        scopesFields[sourcePair[0]] = targetRule;
      }
    });

    this.explicitMappingRules =
      new BehaviorSubject(v[1].collectionsMigrationMode ? {} : v[1].colMappingRules);
    this.explicitMappingMigrationRules =
      new BehaviorSubject(v[1].collectionsMigrationMode ? v[1].colMappingRules : {});

    this.explicitMappingGroup = {
      scopes: {
        flags: this.formBuilder.group(scopesFlags),
        fields: this.formBuilder.group(scopesFields)
      },
      collections: collections,
      collectionsControls: collectionsControls,
      migrationMode: this.formBuilder.group({key: "", target: ""})
    };


  }
}
