import { BehaviorSubject, combineLatest } from 'rxjs';
import {
  map,
  pluck,
  switchMap,
  shareReplay,
  filter,
  distinctUntilChanged,
} from 'rxjs/operators';
import { MnHttpRequest } from './mn.http.request.js';
import { HttpClient } from './mn.http.client.js';
import { MnAdminService } from './mn.admin.service.js';
import { MnTasksService } from './mn.tasks.service.js';
import { MnSecurityService } from './mn.security.service.js';
import { MnPoolsService } from './mn.pools.service.js';
import mnPermissions from './components/mn_permissions.js';

class MnLogsCollectInfoServiceClass {
  constructor(
    http,
    mnAdminService,
    mnTasksService,
    mnSecurityService,
    mnPoolsService,
    mnPermissions
  ) {
    this.http = http;
    this.stream = {};

    this.stream.isEnterprise = mnPoolsService.stream.isEnterprise;
    this.stream.compatVersion55 = mnAdminService.stream.compatVersion55;
    this.stream.taskCollectInfo = mnTasksService.stream.taskCollectInfo;
    let permissionsStream = mnPermissions.stream;
    let settingsReadStream = permissionsStream.pipe(
      pluck('cluster', 'settings', 'read'),
      distinctUntilChanged()
    );

    this.isEnterprise = this.stream.isEnterprise;
    this.mnSecurityService = mnSecurityService;

    this.stream.nodesByCollectInfoStatus = combineLatest(
      mnAdminService.stream.nodesByOtp,
      this.stream.taskCollectInfo.pipe(
        filter((taskCollectInfo) => !!taskCollectInfo),
        pluck('perNode')
      )
    ).pipe(
      map(this.prepareNodesByStatus.bind(this)),
      shareReplay({ refCount: true, bufferSize: 1 })
    );

    this.stream.nodesErrors = this.stream.taskCollectInfo.pipe(
      filter((taskCollectInfo) => !!taskCollectInfo),
      pluck('perNode'),
      map(this.prepareNodesErrors.bind(this)),
      shareReplay({ refCount: true, bufferSize: 1 })
    );

    this.stream.formData = combineLatest([
      this.stream.isEnterprise,
      this.stream.compatVersion55,
      settingsReadStream,
    ]).pipe(
      switchMap(this.formDataSources.bind(this)),
      map(this.unpackData.bind(this)),
      shareReplay({ refCount: true, bufferSize: 1 })
    );

    this.stream.startLogsCollection = new MnHttpRequest(
      this.startLogsCollection.bind(this)
    )
      .addSuccess()
      .addError();

    this.stream.postCancelLogsCollection = new MnHttpRequest(
      this.postCancelLogsCollection.bind(this)
    )
      .addSuccess()
      .addError();

    this.stream.clusterInfo = new BehaviorSubject().pipe(
      switchMap(this.getClusterInfo.bind(this)),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
  }

  startLogsCollection(data) {
    return this.http.post('/controller/startLogsCollection', data);
  }

  postCancelLogsCollection() {
    return this.http.post('/controller/cancelLogsCollection');
  }

  getClusterInfo() {
    return this.http.get('/pools/default/terseClusterInfo?all=true');
  }

  formDataSources([isEnterprise, compatVersion55, serverGroupsRead]) {
    let sources = [this.isEnterprise];
    if (isEnterprise && compatVersion55 && serverGroupsRead) {
      sources.push(this.mnSecurityService.stream.getLogRedaction);
    }
    return combineLatest(sources);
  }

  unpackData([isEnterprise, logRedaction]) {
    return {
      nodes: {},
      logs: {
        logRedactionLevel: logRedaction ? logRedaction.logRedactionLevel : null,
        enableTmpDir: null,
        tmpDir: null,
        enableLogDir: null,
        logDir: null,
      },
      upload: {
        upload: null,
        uploadHost: isEnterprise ? 'uploads.couchbase.com' : null,
        customer: null,
        uploadProxy: null,
        bypassReachabilityChecks: null,
        ticket: null,
      },
    };
  }

  prepareNodesByStatus([nodesByOtp, perNode]) {
    let nodesGroupedByStatus = {};
    Object.keys(perNode).forEach((nodeOtp) => {
      let node = nodesByOtp[nodeOtp] && nodesByOtp[nodeOtp][0];
      perNode[nodeOtp].nodeName = node
        ? node.hostname
        : nodeOtp.replace(/^.*?@/, '');

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
        errors[nodeName].push({ nodeName: nodeName, error: error });
      } else {
        errors[nodeName] = [{ nodeName: nodeName, error: error }];
      }
    };
    Object.values(perNode).forEach((node) => {
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

const MnLogsCollectInfoService = new MnLogsCollectInfoServiceClass(
  HttpClient,
  MnAdminService,
  MnTasksService,
  MnSecurityService,
  MnPoolsService,
  mnPermissions
);
export { MnLogsCollectInfoService };
