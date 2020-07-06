import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {NgbActiveModal} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {pipe} from '/ui/web_modules/rxjs.js';
import {withLatestFrom, map} from '/ui/web_modules/rxjs/operators.js';

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
    NgbActiveModal,
    $rootScope
  ]}

  constructor(mnFormService, mnPoolsService, mnXDCRService, mnBucketsService, mnAdminService, mnAlertsService, activeModal, $rootScope) {
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
  }
}
