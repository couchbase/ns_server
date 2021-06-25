/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {Injectable} from '../web_modules/@angular/core.js';
import {NgbModal} from '../web_modules/@ng-bootstrap/ng-bootstrap.js';
import {BehaviorSubject, combineLatest} from '../web_modules/rxjs.js';
import {map, pluck, switchMap, shareReplay, filter} from '../web_modules/rxjs/operators.js';
import {HttpClient} from '../web_modules/@angular/common/http.js';
import {MnHttpRequest} from './mn.http.request.js';
import {MnAdminService} from './mn.admin.service.js';
import {MnServerGroupsService} from './mn.server.groups.service.js';
import {MnTasksService} from './mn.tasks.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnSecurityService} from './mn.security.service.js';

import {MnLogsCollectInfoStopCollectionComponent} from './mn.logs.collectInfo.stop.collection.component.js';

export {MnLogsCollectInfoService};

class MnLogsCollectInfoService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient,
    MnAdminService,
    MnServerGroupsService,
    MnTasksService,
    NgbModal,
    MnSecurityService,
    MnPoolsService
  ]}

  constructor(http, mnAdminService, mnServerGroupsService, mnTasksService, modalService, mnSecurityService, mnPoolsService) {
    this.modalService = modalService;
    this.http = http;

    this.stream = {};
    let isEnterprise = mnPoolsService.stream.isEnterprise;
    this.taskCollectInfo = mnTasksService.stream.taskCollectInfo;

    this.stream.nodesByCollectInfoStatus =
      combineLatest(mnAdminService.stream.nodesByOtp,
                    this.taskCollectInfo
                      .pipe(filter(taskCollectInfo => !!taskCollectInfo),
                            pluck('perNode')))
      .pipe(map(this.prepareNodesByStatus.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));

    this.stream.nodesErrors = this.taskCollectInfo
      .pipe(filter(taskCollectInfo => !!taskCollectInfo),
            pluck('perNode'),
            map(this.prepareNodesErrors.bind(this)),
            shareReplay({refCount: true, bufferSize: 1}));

    // logRedaction: extra permission check which is not in otherSettings: cluster.settings.read
    this.stream.formData = combineLatest(
      mnServerGroupsService.stream.nodesWithGroupName,
      mnSecurityService.stream.shouldGetLogRedaction,
      isEnterprise
    ).pipe(map(this.unpackData.bind(this)));

    this.stream.startLogsCollection =
      new MnHttpRequest(this.startLogsCollection.bind(this))
        .addSuccess()
        .addError();

    this.stream.postCancelLogsCollection =
      new MnHttpRequest(this.postCancelLogsCollection.bind(this))
        .addSuccess()
        .addError();

    this.stream.clusterInfo =
      (new BehaviorSubject()).pipe(
        switchMap(this.getClusterInfo.bind(this)),
        shareReplay({refCount: true, bufferSize: 1}));
  }

  startLogsCollection(data) {
    return this.http.post("/controller/startLogsCollection", data);
  }

  postCancelLogsCollection() {
    return this.http.post("/controller/cancelLogsCollection");
  }

  getClusterInfo() {
    return this.http.get('/pools/default/terseClusterInfo?all=true');
  }

  cancelLogsCollection() {
    this.modalService.open(MnLogsCollectInfoStopCollectionComponent);
  }

  unpackData([, logRedaction, isEnterprise]) {
    return {
      nodes: {},
      logs: {
        logRedactionLevel: logRedaction.logRedactionLevel,
        enableTmpDir: null,
        tmpDir: null,
        enableLogDir: null,
        logDir: null
      },
      upload: {
        upload: null,
        uploadHost: isEnterprise ? "uploads.couchbase.com": null,
        customer: null,
        uploadProxy: null,
        bypassReachabilityChecks: null,
        ticket: null
      }
    }
  }

  prepareNodesByStatus([nodesByOtp, perNode]) {
    let nodesGroupedByStatus = {};
    Object.keys(perNode).forEach(nodeOtp => {
      let node = nodesByOtp[nodeOtp] && nodesByOtp[nodeOtp][0];
      perNode[nodeOtp].nodeName = node ? node.hostname : nodeOtp.replace(/^.*?@/, '');

      let status = perNode[nodeOtp].status;
      if (nodesGroupedByStatus[status]) {
        nodesGroupedByStatus[status].push(perNode[nodeOtp]);
      } else {
        nodesGroupedByStatus[status] = [perNode[nodeOtp]];
      }
    });
    return nodesGroupedByStatus;
  }

  prepareNodesErrors(perNode) {
    let errors;
    let addError = (nodeName, error) => {
      errors = errors || {};
      if (errors[nodeName]) {
        errors[nodeName].push({nodeName: nodeName, error: error});
      } else {
        errors[nodeName] = [{nodeName: nodeName, error: error}];
      }
    };
    Object.values(perNode).forEach(node => {
      if (node.uploadOutput) {
        addError(node.nodeName, node.uploadOutput);
      }
      if (node.collectionOutput) {
        addError(node.nodeName, node.collectionOutput);
      }
    });

    return errors;
  }
}
