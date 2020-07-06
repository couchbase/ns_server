import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {NgbActiveModal} from '/ui/web_modules/@ng-bootstrap/ng-bootstrap.js';
import {combineLatest, pipe} from '/ui/web_modules/rxjs.js';
import {map, withLatestFrom} from '/ui/web_modules/rxjs/operators.js';

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
    NgbActiveModal,
    MnXDCRService,
    MnFormService,
    MnPoolsService,
    MnAdminService
  ]}

  constructor(activeModal, mnXDCRService, mnFormService, mnPoolsService, mnAdminService) {
    super();
    this.isEditMode = true;
    this.activeModal = activeModal;
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
    this.form = this.mnFormService.create(this)
      .setFormGroup({type: null,
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
      .setPackPipe(pipe(
        withLatestFrom(this.isEnterprise, this.compatVersion55),
        map(this.prepareReplicationSettigns),
        map(data => [this.item.id, data])))
      .setUnpackPipe(map(function (source) {
        return Object.assign({}, source[0], source[1]);
      }))
      .setSource(combineLatest(
        this.getSettingsReplications,
        this.createGetSettingsReplicationsPipe(this.item.id)
      ))
      .setPostRequest(this.postSettingsReplications)
      .setValidation(this.postSettingsReplicationsValidation)
      .successMessage("Settings saved successfully!")
      .clearErrors()
      .success(() => this.activeModal.close());
  }
}
