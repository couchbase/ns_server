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
import {map, takeUntil} from 'rxjs/operators';
import {BehaviorSubject} from 'rxjs';
import {MnSecuritySecretsService} from './mn.security.secrets.service.js';

import {MnPermissions} from './ajs.upgraded.providers.js';

export {MnSecuritySecretsEncryptionDialogComponent};

class MnSecuritySecretsEncryptionDialogComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      template,
      inputs: [
        'secrets'
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnSecuritySecretsService,
    NgbActiveModal,
    MnFormService,
    FormBuilder,
    MnPermissions,
  ]}

  constructor(mnSecuritySecretsService, activeModal, mnFormService, formBuilder, mnPermissions) {
    super();

    this.formBuilder = formBuilder;
    this.activeModal = activeModal;
    this.mnPermissions = mnPermissions;
    this.permissions = mnPermissions.stream;
    this.mnSecuritySecretsService = mnSecuritySecretsService;
    this.mnFormService = mnFormService;
  }

  ngOnInit() {
    this.permissionsAdminSecurityWrite =
      this.mnPermissions.stream
      .pipe(map(permissions => permissions.cluster.admin.security.write));

    this.types = this.mnSecuritySecretsService.types;

    this.selectTab = new BehaviorSubject(this.types[0]);

    this.form = this.mnFormService.create(this)
      .setFormGroup(this.types.reduce((acc, type) => {
        acc[type] = this.formBuilder.group({
          encryptionMethod: 'disabled',
          encryptionSecretId: null,
          dekLifetime: 0,  //in seconds
          dekRotationInterval: 0, //in seconds
        });
        return acc;
      }, {}))
      .setUnpackPipe(map(this.unpackData.bind(this)))
      .setPackPipe(map(this.packData.bind(this)))
      .setSource(this.mnSecuritySecretsService.stream.getEncryptionAtRest)
      .setPostRequest(this.mnSecuritySecretsService.stream.postEncryptionAtRest)
      .successMessage("Encryption at rest config saved successfully!")
      .success(() => {
        this.activeModal.dismiss();
      });

      this.form.group.disable();

      this.httpError = this.mnSecuritySecretsService.stream.postEncryptionAtRest.error;

      this.permissionsAdminSecurityWrite
        .pipe(takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeEnableForm.bind(this));

      this.dropForms = this.types.reduce((acc, type) => {
        acc[type] = this.mnFormService.create(this)
          .setFormGroup({})
          .setPostRequest(this.mnSecuritySecretsService.stream[type +'PostDropAtRestKeys'])
          .trackSubmit()
          .successMessage("Key was dropped successfully!")
          .errorMessage("An error occurred dropping the key.")
          .success(() => this.mnSecuritySecretsService.stream.updateSecretsList.next());
        return acc;
      }, {});

      this.dropErrors = this.types.reduce((acc, type) => {
        acc[type] = this.mnSecuritySecretsService.stream[type +'PostDropAtRestKeys'].errors;
        return acc;
      }, {});

      this.dropFilteredSecrets = this.types.reduce((acc, type) => {
        acc[type] = this.secrets.filter(secret =>
          secret.usage.find(u => u.includes(this.mapTypeToSecret(type) + '-encryption') ))
        return acc;
      }, {});
  }

  doUnpack({encryptionMethod, encryptionSecretId, dekLifetime, dekRotationInterval}) {
    return {
      encryptionMethod: encryptionMethod || 'disabled',
      encryptionSecretId: (encryptionSecretId === null || encryptionSecretId === undefined || encryptionSecretId < 0) ? null : this.secrets.find(i => i.id === encryptionSecretId),
      dekLifetime: (dekLifetime ? dekLifetime : 31536000) / 86_400,
      dekRotationInterval: (dekRotationInterval ? dekRotationInterval : 2592000) / 86_400
    };
  }

  doPack({encryptionMethod, encryptionSecretId, dekLifetime, dekRotationInterval}) {
    return {
      encryptionMethod,
      encryptionSecretId: encryptionMethod === 'secret' ? encryptionSecretId?.id ?? -1 : -1,
      dekLifetime: Math.round(dekLifetime * 86_400),
      dekRotationInterval: Math.round(dekRotationInterval * 86_400)
    };
  }

  unpackData(response) {
    return this.types.reduce((acc, type) => {
      acc[type] = this.doUnpack(response[type] || {});
      return acc;
    }, {});
  }

  packData() {
    const formValues = this.form.group.getRawValue();
    return this.types.reduce((acc, type) => {
      acc[type] = this.doPack(formValues[type]);
      return acc;
    }, {});
  }

  maybeEnableForm(writePermission) {
    this.form.group[writePermission ? "enable" : "disable"]({emitEvent: false});
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

  mapTypeToNames(type) {
    switch (type) {
      case "config": return "Config";
      case "logs": return "Logs";
      case "audit": return "Audit";
      default: return type;
    }
  }
}
