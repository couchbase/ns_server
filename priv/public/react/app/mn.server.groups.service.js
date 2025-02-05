import { BehaviorSubject, combineLatest, timer } from 'rxjs';
import {
  map,
  pluck,
  switchMap,
  shareReplay,
  distinctUntilChanged,
} from 'rxjs/operators';
import { HttpClient } from './mn.http.client.js';
import { MnAdminService } from './mn.admin.service.js';
import mnPermissions from './components/mn_permissions.js';

class MnServerGroupsServiceClass {
  constructor(http, mnAdminService, mnPermissions) {
    this.http = http;
    this.stream = {};

    let permissionsStream = mnPermissions.export;

    let getServerGroups = new BehaviorSubject().pipe(
      switchMap(this.getServerGroups.bind(this))
    );

    let nodesWithGroupName = combineLatest(
      getServerGroups,
      mnAdminService.stream.getNodes
    ).pipe(map(this.addGroupNameToNodes.bind(this)));

    let serverGroupsReadStream = permissionsStream.pipe(
      pluck('cluster', 'server_groups', 'read'),
      distinctUntilChanged()
    );

    this.stream.maybeGetServersWithGroups = combineLatest(
      mnAdminService.stream.isGroupsAvailable,
      serverGroupsReadStream,
      timer(0, 10000)
    ).pipe(
      switchMap(([isGroupsAvailable, serverGroupsRead]) => {
        let hasGroups = isGroupsAvailable && serverGroupsRead;
        return hasGroups ? nodesWithGroupName : mnAdminService.stream.getNodes;
      }),
      shareReplay({ refCount: true, bufferSize: 1 })
    );
  }

  getServerGroups() {
    return this.http.get('/pools/default/serverGroups');
  }

  addGroupNameToNodes([groups, nodes]) {
    let nodesMap = {};

    groups.groups.forEach((group) =>
      group.nodes.forEach((node) => (nodesMap[node.otpNode] = group.name))
    );

    nodes.forEach((node) => (node.groupName = nodesMap[node.otpNode]));

    return nodes;
  }
}

const MnServerGroupsService = new MnServerGroupsServiceClass(
  HttpClient,
  MnAdminService,
  mnPermissions
);
export { MnServerGroupsService };
