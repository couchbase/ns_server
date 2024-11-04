/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {ChangeDetectionStrategy, Component} from '@angular/core';

import {NgbActiveModal} from '@ng-bootstrap/ng-bootstrap';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnFormService} from './mn.form.service.js';
import template from "./mn.security.secrets.encryption.dialog.html";
import {FormBuilder} from '@angular/forms';
import {map} from 'rxjs/operators';
import {MnSecuritySecretsService} from './mn.security.secrets.service.js';
import {timeUnitToSeconds} from './constants/constants.js';

export {MnSecuritySecretsEncryptionDialogComponent};

class MnSecuritySecretsEncryptionDialogComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      template,
      inputs: [
        'secrets',
        'type'
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnSecuritySecretsService,
    NgbActiveModal,
    MnFormService,
    FormBuilder,
  ]}

  constructor(mnSecuritySecretsService, activeModal, mnFormService, formBuilder) {
    super();

    this.formBuilder = formBuilder;
    this.activeModal = activeModal;
    this.mnSecuritySecretsService = mnSecuritySecretsService;
    this.mnFormService = mnFormService;
    this.mapTypeToNames = this.mnSecuritySecretsService.mapTypeToNames;
  }

  ngOnInit() {
    this.form = this.mnFormService.create(this)
      .setFormGroup(this.doUnpack(this.config[this.type]))
      .setPackPipe(map(this.packData.bind(this)))
      .setPostRequest(this.mnSecuritySecretsService.stream.postEncryptionAtRestType)
      .successMessage("Encryption at rest config saved successfully!")
      .success(() => {
        this.activeModal.dismiss();
        this.mnSecuritySecretsService.stream.updateEncryptionAtRest.next();
      });

      this.httpError = this.mnSecuritySecretsService.stream.postEncryptionAtRestType.error;

      this.filteredSecrets = this.secrets.filter(secret => secret.usage.find(u => u.includes(this.mapTypeToSecret(this.type) + '-encryption') ));
  }

  doUnpack({encryptionMethod, encryptionSecretId, dekLifetime, dekRotationInterval}) {
    return {
      encryptionMethod: encryptionMethod || 'disabled',
      encryptionSecretId: (encryptionSecretId === null || encryptionSecretId === undefined || encryptionSecretId < 0) ? null : this.secrets.find(i => i.id === encryptionSecretId),
      dekLifetime: (dekLifetime ? dekLifetime : timeUnitToSeconds.year) / timeUnitToSeconds.day,
      dekRotationInterval: (dekRotationInterval ? dekRotationInterval : timeUnitToSeconds.month) / timeUnitToSeconds.day
    };
  }

  doPack({encryptionMethod, encryptionSecretId, dekLifetime, dekRotationInterval}) {
    return {
      encryptionMethod,
      encryptionSecretId: encryptionMethod === 'secret' ? encryptionSecretId?.id ?? -1 : -1,
      dekLifetime: Math.round(dekLifetime * timeUnitToSeconds.day),
      dekRotationInterval: Math.round(dekRotationInterval * timeUnitToSeconds.day)
    };
  }

  packData() {
    return [this.type, this.doPack(this.form.group.getRawValue())];
  }

  valuesMapping(item) {
    return item ? item.name || '[empty name]' : item;
  }

  mapTypeToSecret(type) {
    switch (type) {
      case "config": return "configuration";
      default: return type;
    }
  }
}
