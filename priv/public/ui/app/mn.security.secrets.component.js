/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Component, ChangeDetectionStrategy} from '@angular/core';
import {MnHelperService} from './mn.helper.service.js';
import {takeUntil, withLatestFrom} from 'rxjs/operators';
import {NgbModal} from '@ng-bootstrap/ng-bootstrap';
import {MnSecuritySecretsService} from './mn.security.secrets.service.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnPermissions} from './ajs.upgraded.providers.js';
import template from "./mn.security.secrets.html";
import {MnSecuritySecretsAddDialogComponent} from './mn.security.secrets.add.dialog.component.js';
import {MnSecuritySecretsEncryptionDialogComponent} from './mn.security.secrets.encryption.dialog.component.js';
import {Subject} from 'rxjs';

export {MnSecuritySecretsComponent};

class MnSecuritySecretsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      template,
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnPermissions,
    MnSecuritySecretsService,
    MnHelperService,
    NgbModal
  ]}

  constructor(mnPermissions, mnSecuritySecretsService, mnHelperService, modalService) {
    super();

    this.modalService = modalService;
    this.permissions = mnPermissions.stream;

    this.sorter = mnHelperService.createSorter('creationDateTime', true);
    this.filter = mnHelperService.createFilter(this,
                                               ['name', 'type', 'usage', 'creationDateTime'],
                                               true);

    this.onAddSecretClick = new Subject();
    this.onAddSecretClick
      .pipe(withLatestFrom(mnSecuritySecretsService.stream.getSecrets),
            takeUntil(this.mnOnDestroy))
      .subscribe(([, secrets]) => {
        const ref = this.modalService.open(MnSecuritySecretsAddDialogComponent);
        ref.componentInstance.item = null;
        ref.componentInstance.secrets = secrets;
      });

    this.onEncryptionAtRestClick = new Subject();
    this.onEncryptionAtRestClick
      .pipe(withLatestFrom(mnSecuritySecretsService.stream.getSecrets),
            takeUntil(this.mnOnDestroy))
      .subscribe(([, secrets]) => {
        const ref = this.modalService.open(MnSecuritySecretsEncryptionDialogComponent);
        ref.componentInstance.secrets = secrets;
      });

    this.secrets = mnSecuritySecretsService.stream.getSecrets;

    this.filteredSecrets = this.secrets
      .pipe(this.filter.pipe,
            this.sorter.pipe);
  }

  trackByMethod(i, item) {
    return item.id;
  }
}
