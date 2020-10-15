import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {pipe, Subject, of} from '/ui/web_modules/rxjs.js';
import {withLatestFrom, map, filter, switchMap, pluck, shareReplay,
        takeUntil, startWith} from '/ui/web_modules/rxjs/operators.js';

import {MnLifeCycleHooksToStream} from "./mn.core.js";

import {MnPoolsService} from "./mn.pools.service.js";
import {MnXDCRService} from "./mn.xdcr.service.js";
import {MnCollectionsService} from './mn.collections.service.js';
import {MnHelperService} from "./mn.helper.service.js";

export {MnXDCRAddRepMappingComponent};

class MnXDCRAddRepMappingComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-mapping",
      templateUrl: "/ui/app/mn.xdcr.add.rep.mapping.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "explicitMappingRules",
        "explicitMappingMigrationRules",
        "explicitMappingGroup",
        "group",
        "bucket"
      ]
    })
  ]}

  static get parameters() { return [
    MnPoolsService,
    MnXDCRService,
    MnHelperService,
    MnCollectionsService
  ]}

  constructor(mnPoolsService, mnXDCRService, mnHelperService, mnCollectionsService) {
    super();

    this.mnCollectionsService = mnCollectionsService;
    this.mnHelperService = mnHelperService;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.postCreateReplication = mnXDCRService.stream.postCreateReplication;
    this.postSettingsReplicationsValidation =
      mnXDCRService.stream.postSettingsReplicationsValidation;

    this.addExplicitMappingMigrationRules = new Subject();

    this.addExplicitMappingMigrationRules
      .pipe(filter(() => !!this.explicitMappingGroup.migrationMode.value.key),
            map(() => [this.explicitMappingGroup.migrationMode.value.key,
                       this.explicitMappingGroup.migrationMode.value.target]),
            takeUntil(this.mnOnDestroy))
      .subscribe(v => {
        let rules = this.explicitMappingMigrationRules.getValue();
        rules[v[0]] = v[1];
        this.explicitMappingMigrationRules.next(rules);
        resetExplicitMappingMigrationGroup.bind(this)();
      });

    function resetExplicitMappingMigrationGroup() {
      this.explicitMappingGroup.migrationMode.patchValue({key: "", target: ""});
    }
  }

  ngOnInit() {
    this.group.get("collectionsExplicitMapping").valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(enabled => {
        if (enabled) {
          this.group.get("collectionsMigrationMode").patchValue(false, {onlySelf: true});
        }
      });

    this.group.get("collectionsMigrationMode").valueChanges
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(enabled => {
        if (enabled) {
          this.group.get("collectionsExplicitMapping").patchValue(false, {onlySelf: true});
        }
      });

    let hasSourceBucketField = this.group.get("fromBucket");
    if (hasSourceBucketField) {
      hasSourceBucketField.valueChanges
        .pipe(startWith(hasSourceBucketField.value),
              takeUntil(this.mnOnDestroy))
        .subscribe(v => {
          let action = v ? "enable" : "disable";
          this.group.get("collectionsExplicitMapping")[action]({onlySelf: true});
          this.group.get("collectionsMigrationMode")[action]({onlySelf: true});
        });
    }

    this.scopesFilter = this.mnHelperService.createFilter("name");

    this.scopes =
      (this.bucket ? of(this.bucket) : this.group.get("fromBucket").valueChanges)
      .pipe(filter(v => !!v),
            switchMap(bucketName => this.mnCollectionsService.getManifest(bucketName)),
            pluck("scopes"),
            this.scopesFilter.pipe,
            shareReplay({refCount: true, bufferSize: 1}));

    this.scopesPaginator =
      this.mnHelperService.createPagenator(this, this.scopes, "scopesPage");
  }
}
