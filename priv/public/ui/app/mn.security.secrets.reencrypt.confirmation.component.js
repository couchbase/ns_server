/*
Copyright 2024-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { Component, ChangeDetectionStrategy } from '@angular/core';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { MnSecuritySecretsService } from './mn.security.secrets.service.js';
import { map } from 'rxjs/operators';

import { MnFormService } from './mn.form.service.js';
import template from "./mn.security.secrets.reencrypt.confirmation.html";

export { MnSecuritySecretsReencryptConfirmationComponent };

class MnSecuritySecretsReencryptConfirmationComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      template,
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "type",
        "bucketName"
      ]
    })
  ]}

  static get parameters() { return [
    NgbActiveModal,
    MnSecuritySecretsService,
    MnFormService
  ]}

  constructor(activeModal, mnSecuritySecretsService, mnFormService) {
    super();
    this.activeModal = activeModal;
    this.mnFormService = mnFormService;
    this.mnSecuritySecretsService = mnSecuritySecretsService;
    this.mapTypeToNames = mnSecuritySecretsService.mapTypeToNames;
  }

  ngOnInit() {
    this.form = this.mnFormService.create(this)
      .setFormGroup({})
      .setPackPipe(map(() => [this.type, this.bucketName]))
      .setPostRequest(this.mnSecuritySecretsService.stream.postDropAtRestKeys)
      .showGlobalSpinner()
      .successMessage("Re-encryption was successfully initiated!")
      .errorMessage("An error occurred during re-encryption initialization.")
      .success(() => {
        this.activeModal.close();
        this.mnSecuritySecretsService.stream.updateSecretsList.next();
      }).error(() => {
        this.activeModal.close();
      });
  }
}
