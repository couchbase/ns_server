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
import template from "./mn.security.secrets.add.dialog.html";
import {FormBuilder} from '@angular/forms';
import {UIRouter} from '@uirouter/angular';
import {map, startWith, takeUntil, first} from 'rxjs/operators';
import {MnSecuritySecretsService} from './mn.security.secrets.service.js';

import {MnPermissions} from './ajs.upgraded.providers.js';

export {MnSecuritySecretsAddDialogComponent};

class MnSecuritySecretsAddDialogComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      template,
      inputs: [
        'item'
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnSecuritySecretsService,
    NgbActiveModal,
    MnFormService,
    UIRouter,
    FormBuilder,
    MnPermissions,
  ]}

  constructor(mnSecuritySecretsService, activeModal, mnFormService, uiRouter, formBuilder, mnPermissions) {
    super();

    this.formBuilder = formBuilder;
    this.activeModal = activeModal;
    this.mnPermissions = mnPermissions;
    this.permissions = mnPermissions.stream;
    this.mnSecuritySecretsService = mnSecuritySecretsService;
    this.mnFormService = mnFormService;
    this.uiRouter = uiRouter;
  }

  ngOnInit() {
    this.permissions
      .pipe(map(p => p.bucketNames['.views!read']),
            first())
      .subscribe(this.doInit.bind(this));
  }

  doInit(buckets) {
    this.permissionsAdminSecurityWrite = this.mnPermissions.stream
      .pipe(map(permissions => permissions.cluster.admin.security.write));

    this.bucketNames = ['*', ...buckets || []];

    this.form = this.mnFormService.create(this)
      .setFormGroup({
        name: '',
        type: 'awskms-aes-key-256',
        'generated-secret': this.formBuilder.group({
          autoRotation: false,
          rotationIntervalInDays: null,
          nextRotationTime: this.formBuilder.group({
            date: new Date(),
            hour: null,
            minute: null
          })
        }),
        'aws-secret': this.formBuilder.group({
          keyARN: "",
          region: "",
          useIMDS: false,
          credentialsFile: "",
          configFile: "",
          profile: ""
        }),
        usage: this.formBuilder.group(this.bucketNames.reduce((acc, bucket) => {
          acc['bucket-encryption-' + bucket] = false;
          return acc;
        }, {
          'configuration-encryption': false,
          'secrets-encryption': false,
        }))
      })
      .setPackPipe(map(this.packData.bind(this)))
      .setPostRequest(this.item ? this.mnSecuritySecretsService.stream.putSecret : this.mnSecuritySecretsService.stream.postSecret)
      .setReset(this.uiRouter.stateService.reload)
      .successMessage(this.item ? "Secret updated successfully!" : "Secret created successfully!")
      .success(() => {
        this.mnSecuritySecretsService.stream.updateSecretsList.next();
        this.activeModal.dismiss();
      });

      this.form.group.disable();

      this.httpError = this.item ?
        this.mnSecuritySecretsService.stream.putSecret.error : this.mnSecuritySecretsService.stream.postSecret.error;

      this.formType =
        this.form.group.get('type').valueChanges
        .pipe(startWith(this.form.group.get('type').value));

      this.isAutoRotationEnabled =
        this.form.group.get('generated-secret.autoRotation').valueChanges
        .pipe(startWith(this.form.group.get('generated-secret.autoRotation').value));

      this.permissionsAdminSecurityWrite
        .pipe(takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeEnableForm.bind(this));

      this.isAutoRotationEnabled
        .pipe(takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeEnableRotation.bind(this));

    if (this.item) {
      setTimeout(() => {
        this.form.group.patchValue(this.unpackData(this.item));
        this.form.group.get('type').disable();
        this.form.group.get('aws-secret.region').disable();
        this.form.group.get('aws-secret.keyARN').disable();
      });
    }
  }

  maybeEnableRotation(enable) {
    this.form.group.get('generated-secret.rotationIntervalInDays')[enable ? "enable" : "disable"]();
    this.form.group.get('generated-secret.nextRotationTime')[enable ? "enable" : "disable"]();
  }

  maybeEnableForm(writePermission) {
    this.form.group[writePermission ? "enable" : "disable"]({emitEvent: false});
  }

  setDate(value) {
    this.form.group.get('generated-secret.nextRotationTime.date').setValue(new Date(value));
  }

  unpackData(item) {
    let rv = {
      name: item.name,
      type: item.type,
      usage: item.usage.reduce((acc, v) => {
        acc[v] = true;
        return acc;
      }, {})
    };

    if (rv.type === "auto-generated-aes-key-256") {
      if (item.data.autoRotation) {
        const localTime = new Date(item.data.nextRotationTime);
        rv['generated-secret'] = {
          autoRotation: item.data.autoRotation,
          rotationIntervalInDays: item.data.rotationIntervalInDays,
          nextRotationTime: {
            date: localTime,
            hour: localTime.getHours(),
            minute: localTime.getMinutes(),
          }
        };
      } else {
        rv['generated-secret'] = {
          autoRotation: item.data.autoRotation
        };
      }
    } else {
      rv['aws-secret'] = item.data
    }
    return rv;
  }

  packData() {
    let value = this.form.group.getRawValue();
    let {usage, name, type, 'generated-secret': generatedSecret, 'aws-secret': awsSecret} = value;

    let data = {};
    if (type === 'auto-generated-aes-key-256') {
      const {rotationIntervalInDays, nextRotationTime, autoRotation} = generatedSecret;
      data = {autoRotation};
      if (autoRotation) {
        data.rotationIntervalInDays = rotationIntervalInDays;
        const {date, hour, minute} = nextRotationTime;
        var copiedDate = new Date(date.getTime());
        copiedDate.setHours(hour || 0);
        copiedDate.setMinutes(minute || 0);
        copiedDate.setSeconds(0);
        copiedDate.setMilliseconds(0);
        data.nextRotationTime = copiedDate.toISOString();
      }
    } else {
      data = awsSecret;
    }

    return [{ name, type, usage: Object.keys(usage).filter(v => usage[v]), data}, this.item?.id];
  }
}
