/*
Copyright 2024-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {HttpParams, HttpHeaders} from '@angular/common/http';
import {BehaviorSubject, combineLatest} from 'rxjs';
import {switchMap, shareReplay, map, pluck,
        distinctUntilChanged} from 'rxjs/operators';

import {MnHttpRequest} from './mn.http.request.js';
import {HttpClient} from './mn.http.client.js';
import {MnAdminService} from './mn.admin.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import mnPermissions from './components/mn_permissions.js'

class MnSecurityServiceClass {
  constructor(http, mnAdminService, mnPoolsService, mnPermissions) {
    this.http = http;

    let isEnterprise = mnPoolsService.stream.isEnterprise;
    let compatVersion55 = mnAdminService.stream.compatVersion55;
    let permissionsStream = mnPermissions.stream;
    let settingsReadStream =
        permissionsStream.pipe(pluck('cluster','settings','read'),
                               distinctUntilChanged());

    this.stream = {};

    this.mnAdminService = mnAdminService;

    this.stream.getSaslauthdAuth =
      (new BehaviorSubject()).pipe(
        switchMap(this.getSaslauthdAuth.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getCertificate =
      (new BehaviorSubject()).pipe(
        switchMap(this.getCertificate.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getSettingsSecurity =
      (new BehaviorSubject())
      .pipe(switchMap(this.getSettingsSecurity.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getLogRedaction =
      (new BehaviorSubject()).pipe(
        switchMap(this.getLogRedaction.bind(this)));

    this.stream.getClusterEncryption =
        this.stream.getSettingsSecurity
        .pipe(pluck('clusterEncryptionLevel'));

    this.stream.getClientCertAuth =
      (new BehaviorSubject()).pipe(
        switchMap(this.getClientCertAuth.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getAudit =
      (new BehaviorSubject()).pipe(
        switchMap(this.getAudit.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getUserActivity =
      (new BehaviorSubject()).pipe(
        switchMap(this.getUserActivity.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getUIUserRoles =
      (new BehaviorSubject()).pipe(
        switchMap(this.getUIUserRoles.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));
    this.stream.getUIUserGroups =
      (new BehaviorSubject()).pipe(
        switchMap(this.getUIUserGroups.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getSaml =
      (new BehaviorSubject()).pipe(
        switchMap(this.getSaml.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getAuditDescriptors =
      (new BehaviorSubject()).pipe(
        switchMap(this.getAuditDescriptors.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.getAuditNonFilterableDescriptors =
      (new BehaviorSubject()).pipe(
        switchMap(this.getAuditNonFilterableDescriptors.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.postLogRedaction =
      new MnHttpRequest(this.postLogRedaction.bind(this))
      .addSuccess()
      .addError();

    this.stream.postSettingsSecurity =
      new MnHttpRequest(this.postSettingsSecurity.bind(this))
      .addSuccess()
      .addError();

    this.stream.postClientCertAuth =
      new MnHttpRequest(this.postClientCertAuth.bind(this))
      .addSuccess()
      .addError();

    this.stream.postAuditValidation =
      new MnHttpRequest(this.postAudit(true).bind(this))
      .addSuccess()
      .addError();

    this.stream.postAudit =
      new MnHttpRequest(this.postAudit(false).bind(this))
      .addSuccess()
      .addError();

    this.stream.postUserActivityValidation =
      new MnHttpRequest(this.postUserActivity(true).bind(this))
      .addSuccess()
      .addError();

    this.stream.postUserActivity =
      new MnHttpRequest(this.postUserActivity(false).bind(this))
      .addSuccess()
      .addError();

    this.stream.postSaml =
      new MnHttpRequest(this.postSaml(false).bind(this))
      .addSuccess()
      .addError();

    this.stream.postSamlValidation =
      new MnHttpRequest(this.postSaml(true).bind(this))
      .addSuccess()
      .addError();

    this.stream.prepareOtherSettingsFormValues =
      combineLatest([
        isEnterprise,
        compatVersion55,
        settingsReadStream
      ])
      .pipe(switchMap(this.getOtherSettingsSources.bind(this)),
            map(this.getOtherSettings.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));
  }

  postAudit(validate) {
    return (data) => {
      return this.http.post("/settings/audit", data, {
        params: new HttpParams().set("just_validate", validate ? 1 : 0)
      });
    }
  }

  postUserActivity(validate) {
    return (data) => {
      data.trackedRoles = data.trackedRoles.join(',');
      data.trackedGroups = data.trackedGroups.join(',');
      return this.http.post("/settings/security/userActivity", data, {
        params: new HttpParams().set("just_validate", validate ? 1 : 0)
      });
    }
  }

  postSaml(validate) {
    return (data) => {
      return this.http.post("/settings/saml", data, {
        params: new HttpParams().set("just_validate", validate ? 1 : 0)
      });
    }
  }

  postSettingsSecurity(data) {
    return this.http.post("/settings/security", data);
  }

  getSettingsSecurity() {
    return this.http.get("/settings/security");
  }

  getAuditDescriptors() {
    return this.http.get("/settings/audit/descriptors");
  }

  getAuditNonFilterableDescriptors() {
    return this.http
      .get("/settings/audit/nonFilterableDescriptors")
      .pipe(map(data => data.map((desc) => {
        desc.nonFilterable = true;
        return desc;
      })));
  }

  getAudit() {
    return this.http.get("/settings/audit");
  }

  getUserActivity() {
    return this.http.get("/settings/security/userActivity");
  }

  getUIUserRoles() {
    return this.http.get("/_uiroles");
  }

  getUIUserGroups() {
    return this.http.get("/settings/rbac/groups");
  }

  getSaml() {
    return this.http.get("/settings/saml");
  }

  getSaslauthdAuth() {
    return this.http.get("/settings/saslauthdAuth");
  }

  getClientCertAuth() {
    return this.http.get("/settings/clientCertAuth");
  }

  postClientCertAuth(data) {
    return this.http.post("/settings/clientCertAuth", data[0], {
      headers: new HttpHeaders().set("isNotForm", data[1])
    });
  }

  getLogRedaction() {
    return this.http.get("/settings/logRedaction");
  }

  postLogRedaction(data) {
    return this.http.post("/settings/logRedaction", data);
  }

  getCertificate() {
    return this.http.get("/pools/default/certificate", {
      params: new HttpParams().set("extended", true)
    });
  }

  getOtherSettingsSources([isEnterprise, compatVersion55, settingsRead]) {
    let sources = [
      this.mnAdminService.stream.uiSessionTimeout
    ];
    if (isEnterprise) {
      sources.push(this.stream.getClusterEncryption);
      if (compatVersion55 && settingsRead) {
        sources.push(this.stream.getLogRedaction);
      }
    }
    return combineLatest(sources);
  }

  getOtherSettings([session, encryption, redaction]) {
    return {
      logRedactionLevel: {
        logRedactionLevel: redaction ? redaction['logRedactionLevel'] : null
      },
      settingsSecurity: {
        uiSessionTimeout: (Number(session) / 60) || 0,
        clusterEncryptionLevel: (encryption || 'control')
      }
    }
  }
}

const MnSecurityService = new MnSecurityServiceClass(HttpClient, MnAdminService, MnPoolsService, mnPermissions);
export {MnSecurityService};
