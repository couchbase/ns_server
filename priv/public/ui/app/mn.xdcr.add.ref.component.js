/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {NgbActiveModal} from '@ng-bootstrap/ng-bootstrap';
import {first, map, takeUntil, startWith} from 'rxjs/operators';
import {merge} from 'rxjs';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnFormService} from "./mn.form.service.js";
import {MnPoolsService} from './mn.pools.service.js';
import {MnAdminService} from './mn.admin.service.js';
import {MnXDCRService} from './mn.xdcr.service.js';
import {clone} from 'ramda';
import template from "./mn.xdcr.add.ref.html";

export {MnXDCRAddRefComponent};

class MnXDCRAddRefComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      template,
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item"
      ],
    })
  ]}

  static get parameters() { return [
    MnFormService,
    MnPoolsService,
    MnAdminService,
    MnXDCRService,
    NgbActiveModal
  ]}

  constructor(mnFormService, mnPoolsService, mnAdminService, mnXDCRService, activeModal) {
    super();

    this.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.compatVersion79 = mnAdminService.stream.compatVersion79;
    this.majorMinorVersion = mnAdminService.stream.majorMinorVersion;
    this.postRemoteClusters = mnXDCRService.stream.postRemoteClusters;
    this.postXdcr = mnXDCRService.stream.postRemoteClusters;
    this.postXdcrConnectionPreCheck = mnXDCRService.stream.postXdcrConnectionPreCheck;
    this.activeModal = activeModal;

    this.formHelper =
      mnFormService.create(this)
      .setFormGroup({useClientCertificate: false});

    this.form = mnFormService.create(this);
    this.form
      .setFormGroup({name: "",
                     hostname: "",
                     username: "",
                     password: "",
                     demandEncryption: false,
                     encryptionType: null,
                     certificate: "",
                     clientCertificate: "",
                     clientKey: "",
                     network_type: ""})
      .setPackPipe(map(this.pack.bind(this)))
      .setPostRequest(this.postRemoteClusters)
      .clearErrors()
      .successMessage("Cluster reference saved successfully!")
      .showGlobalSpinner()
      .success(function () {
        activeModal.close();
        mnXDCRService.stream.updateRemoteClusters.next();
      });

    this.checkForm = mnFormService.create(this);
    this.checkForm
      .setFormGroup({})
      .setPackPipe(map(this.pack.bind(this)))
      .setPostRequest(this.postXdcrConnectionPreCheck)
      .clearErrors()
      .showGlobalSpinner();

    this.result = merge(
      this.postXdcrConnectionPreCheck.error,
      this.postXdcrConnectionPreCheck.success
    ).pipe(
      startWith(null),
      map((resp) => {
        if (resp && resp.result) {
          return JSON.stringify(resp.result, null, 2);
        } else {
          return null;
        }
      }));

    this.form.submit
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.checkForm.doClearErrors.bind(this.checkForm));

    this.checkForm.submit
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(this.form.doClearErrors.bind(this.form));
  }

  ngOnInit() {
    this.isNew = !this.item;

    this.isEnterprise
      .pipe(first())
      .subscribe(this.setInitialValues.bind(this));
  }

  setInitialValues(isEnterprise) {
    var value;
    if (this.item) {
      value = clone(this.item);
    } else {
      value = {username: 'Administrator'};
    }
    if (!value.encryptionType && isEnterprise) {
      value.encryptionType = "half";
    }
    this.form.group.patchValue(value, {emitEvent: false});
    this.formHelper.group.patchValue({
      useClientCertificate: !!value.clientCertificate || !!value.clientKey
    });
  }

  pack() {
    let value = clone(this.form.group.value);
    if (!this.formHelper.group.value.useClientCertificate) {
      value.clientCertificate = "";
      value.clientKey = "";
    }
    return [value, this.item && this.item.name];
  }
}
