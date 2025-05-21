/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {UIRouter} from '@uirouter/angular';
import {Component, ChangeDetectionStrategy} from '@angular/core';
import {filter, map, switchMap, withLatestFrom, takeUntil} from 'rxjs/operators';
import {BehaviorSubject, pipe, empty} from 'rxjs';
import { Validators } from '@angular/forms';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnWizardService} from './mn.wizard.service.js';
import {MnAuthService} from "./mn.auth.service.js";
import {MnFormService} from "./mn.form.service.js";
import {MnPoolsService} from "./mn.pools.service.js"
import {MnHelperService} from "./mn.helper.service.js";
import {MnSecurityService} from "./mn.security.service.js";
import {MnPools, $rootScope} from "./ajs.upgraded.providers.js";
import template from "./mn.wizard.join.cluster.html";

export {MnWizardJoinClusterComponent};

class MnWizardJoinClusterComponent extends MnLifeCycleHooksToStream {

  static get annotations() { return [
    new Component({
      template,
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnPoolsService,
    MnSecurityService,
    MnWizardService,
    MnAuthService,
    MnFormService,
    UIRouter,
    'clientCertificates',
    MnPools,
    $rootScope,
    MnHelperService
  ]}

  constructor(mnPoolsService, mnSecurityService, mnWizardService, mnAuthService, mnFormService, uiRouter, clientCertificates, mnPools, $rootScope, mnHelperService) {
    super();

    this.clientCertificates = clientCertificates;
    const uploadedCert = this.clientCertificates.data[0]?.type === 'uploaded';

    this.mnHelperService = mnHelperService;

    this.focusFieldSubject = new BehaviorSubject("hostname");
    this.joinClusterForm = mnWizardService.wizardForm.joinCluster;
    this.joinClusterHttp = mnWizardService.stream.joinClusterHttp;

    const clusterAdminGroup = this.joinClusterForm.get('clusterAdmin');
    const clientCertAuthControl = clusterAdminGroup.get('clientCertAuth');
    clientCertAuthControl.setValue(uploadedCert ? 'true' : 'false');
    const userControl = clusterAdminGroup.get('user');
    const passwordControl = clusterAdminGroup.get('password');

    // need to make user/password validation contingent on clientCertAuth
    const updateUserValidation = (clientCertAuthValue) => {
      if (clientCertAuthValue === 'true') {
        userControl.clearValidators();
        passwordControl.clearValidators();
      } else {
        userControl.setValidators(Validators.required);
        passwordControl.setValidators(Validators.required);
      }
      userControl.updateValueAndValidity();
      passwordControl.updateValueAndValidity();
    };

    // Set initial validation state
    updateUserValidation(clientCertAuthControl.value);

    // Subscribe to changes
     clientCertAuthControl.valueChanges
       .pipe(takeUntil(this.mnOnDestroy))
       .subscribe(updateUserValidation);

    this.certificate = mnPoolsService.stream.isEnterprise
      .pipe(switchMap((v) => v ? mnSecurityService.stream.getCertificate : empty() ));

    this.form = mnFormService.create(this);

    this.form
      .setPackPipe(pipe(
        filter(this.isValid.bind(this)),
        withLatestFrom(mnPoolsService.stream.isEnterprise),
        map(([, isEnterprise]) => {
          let rv = {};
          var nodeStorage = this.joinClusterForm.get("clusterStorage");
          rv.hostname = nodeStorage.get("hostname").value;
          rv.dataPath = nodeStorage.get("storage.path").value;
          rv.indexPath = nodeStorage.get("storage.index_path").value;
          rv.eventingPath = nodeStorage.get("storage.eventing_path").value;
          rv.javaHome = nodeStorage.get("storage.java_home").value;
          if (isEnterprise) {
            rv.analyticsPath = nodeStorage.get("storage.cbas_path").value;
          }
          return rv;
        })
      ))
      .setPostRequest(mnWizardService.stream.postNodeInitHttp)
      .setPackPipe(map(() => {
        var data = this.joinClusterForm.get("clusterAdmin").value;
        var services = this.joinClusterForm.get("services.flag");
        data.newNodeHostname = this.joinClusterForm.get("clusterStorage.hostname").value;
        var servicesValue = mnWizardService.getServicesValues(services);
        data.services = '';
        if (servicesValue.length) {
          data.services = mnWizardService.getServicesValues(services).join(",");
        }
        if (data.clientCertAuth === 'true') {
          delete data.user;
          delete data.password;
        }
        return data;
      }))
      .setPostRequest(this.joinClusterHttp)
      .setPackPipe(map(() => [this.joinClusterForm.get("clusterAdmin").value, false]))
      .setPostRequest(mnAuthService.stream.postUILogin)
      .clearErrors()
      .showGlobalSpinner()
      .success(() => {
        let services = this.joinClusterForm.get("services.flag");
        let servicesAsObject =
          this.mnHelperService.stringToObject(mnWizardService.getServicesValues(services).join(','));
        $rootScope.mnGlobalSpinnerFlag = true;
        $rootScope.$broadcast("maybeShowMemoryQuotaDialog", servicesAsObject);
        mnPools.clearCache();
        uiRouter.urlRouter.sync();
      });
  }

  isValid() {
    return !this.joinClusterForm.invalid;
  }
}
