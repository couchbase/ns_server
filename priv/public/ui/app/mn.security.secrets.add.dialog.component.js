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
import {MnHelperService} from "./mn.helper.service.js";

import {MnPermissions} from './ajs.upgraded.providers.js';

export {MnSecuritySecretsAddDialogComponent};

class MnSecuritySecretsAddDialogComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      template,
      inputs: [
        'item',
        'secrets'
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
    MnHelperService
  ]}

  constructor(mnSecuritySecretsService, activeModal, mnFormService, uiRouter, formBuilder, mnPermissions, mnHelperService) {
    super();

    this.formBuilder = formBuilder;
    this.activeModal = activeModal;
    this.permissions = mnPermissions.stream;
    this.mnSecuritySecretsService = mnSecuritySecretsService;
    this.mnFormService = mnFormService;
    this.uiRouter = uiRouter;
    this.toggler = mnHelperService.createToggle();
  }

  ngOnInit() {
    this.permissions
      .pipe(map(p => p.bucketNames['.views!read']),
            first())
      .subscribe(this.doInit.bind(this));
  }

  doInit(buckets) {
    this.bucketNames = buckets || [];
    this.options = ['secrets', 'bucket', ...this.mnSecuritySecretsService.types];
    this.mapTypeToNames = this.mnSecuritySecretsService.mapTypeToNames;

    this.form = this.mnFormService.create(this)
      .setFormGroup({
        name: '',
        type: 'awskms-aes-key-256',
        'generated-secret': this.formBuilder.group({
          encryptBy: 'nodeSecretManager',
          encryptSecretId: null,
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
        usageBuckets: this.formBuilder.group(this.bucketNames.reduce((acc, bucket) => {
          //set false by default for editing mode and true for adding mode
          acc['bucket-encryption-' + bucket] = !this.item;
          return acc;
        }, {})),
        usage: this.formBuilder.group(this.options.reduce((acc, v) => {
          //set false by default for editing mode and true for adding mode
          acc[v + '-encryption'] = !this.item;
          return acc;
        }, {}))
      })
      .setPackPipe(map(this.packData.bind(this)))
      .setPostRequest(this.item ? this.mnSecuritySecretsService.stream.putSecret : this.mnSecuritySecretsService.stream.postSecret)
      .setReset(this.uiRouter.stateService.reload)
      .successMessage(this.item ? "Secret updated successfully!" : "Secret created successfully!")
      .success(() => {
        this.mnSecuritySecretsService.stream.updateSecretsList.next();
        this.activeModal.dismiss();
      });

      this.filteredSecrets = this.secrets.filter(secret => secret.usage.find(u => u.includes('secrets-encryption')));

      this.httpError = this.item ?
        this.mnSecuritySecretsService.stream.putSecret.error : this.mnSecuritySecretsService.stream.postSecret.error;

      this.formType =
        this.form.group.get('type').valueChanges
        .pipe(startWith(this.form.group.get('type').value));

      const isAutoRotationEnabled =
        this.form.group.get('generated-secret.autoRotation').valueChanges
        .pipe(startWith(this.form.group.get('generated-secret.autoRotation').value));

      const isDataEnabled =
        this.form.group.get('usage.bucket-encryption').valueChanges
        .pipe(startWith(this.form.group.get('usage.bucket-encryption').value));

      const usageBucketsChanged =
        this.form.group.get('usageBuckets').valueChanges
        .pipe(startWith(this.form.group.get('usageBuckets').value));

      isDataEnabled
        .pipe(takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeToggleAllBuckets.bind(this));

      isAutoRotationEnabled
        .pipe(takeUntil(this.mnOnDestroy))
        .subscribe(this.maybeEnableRotation.bind(this));

      usageBucketsChanged
        .pipe(takeUntil(this.mnOnDestroy))
        .subscribe(this.handleUsageBucketsChange.bind(this));

    if (this.item) {
      setTimeout(() => {
        this.form.group.patchValue(this.unpackData(this.item));
        this.form.group.get('type').disable();
        this.form.group.get('aws-secret.region').disable();
        this.form.group.get('aws-secret.keyARN').disable();
      });
    }
  }

  isAllUsesSelected() {
    return Object.values(this.form.group.get('usage').value).every(v => v);
  }

  getSelected() {
    return this.options.filter(v => this.form.group.get('usage').value[v + '-encryption']).map(this.mapTypeToNames).join(', ');
  }

  maybeToggleAllBuckets(value) {
    this.form.group.get('usageBuckets').patchValue(this.bucketNames.reduce((acc, bucket) => {
      acc['bucket-encryption-' + bucket] = value;
      return acc;
    }, {}), {emitEvent: false});
  }

  handleUsageBucketsChange(value) {
    this.form.group.get('usage.bucket-encryption').setValue(Object.values(value).every(v => v), {emitEvent: false});
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
        //it is safe to unpack both usage and usageBuckets equally since
        //angular's patchValue filters out unknown keys
        acc[this.unpackUsage(v)] = true;
        return acc;
      }, {}),
      usageBuckets: item.usage.reduce((acc, v) => {
        //it is safe to unpack both usage and usageBuckets equally since
        //angular's patchValue filters out unknown keys
        acc[this.unpackUsage(v)] = true;
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
      const {encryptSecretId, encryptBy} = item.data;
      rv['generated-secret'].encryptBy = encryptBy;
      if (encryptBy === 'clusterSecret') {
        rv['generated-secret']['encryptSecretId'] = (encryptSecretId === null || encryptSecretId === undefined || encryptSecretId < 0) ? null : this.secrets.find(i => i.id === encryptSecretId);
      }
    } else {
      rv['aws-secret'] = item.data
    }
    return rv;
  }

  packData() {
    let value = this.form.group.getRawValue();
    let {usage, usageBuckets, name, type, 'generated-secret': generatedSecret, 'aws-secret': awsSecret} = value;

    let data = {};
    if (type === 'auto-generated-aes-key-256') {
      const {rotationIntervalInDays, nextRotationTime, autoRotation, encryptBy, encryptSecretId} = generatedSecret;
      data = {autoRotation, encryptBy};
      if (encryptBy === 'clusterSecret') {
        data.encryptSecretId = encryptSecretId?.id ?? -1;
      }
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

    let usageToSend = Object.keys(usage).filter(v => usage[v]).map(this.packUsage);
    usageToSend = usageToSend.concat(Object.keys(usageBuckets).filter(v => usageBuckets[v]));

    return [{ name, type, usage: usageToSend, data}, this.item?.id];
  }

  packUsage(usage) {
    switch (usage) {
      case 'config-encryption':
        return 'configuration-encryption';
      case 'bucket-encryption':
          return 'bucket-encryption-*';
      default:
        return usage;
    }
  }

  unpackUsage(usage) {
    switch (usage) {
      case 'configuration-encryption':
        return 'config-encryption';
      case 'bucket-encryption-*':
        return 'bucket-encryption';
      default:
        return usage;
    }
  }

  valuesMapping(item) {
    return item ? item.name || '[empty name]' : item;
  }
}
