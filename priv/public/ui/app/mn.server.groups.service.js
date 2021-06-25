/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {BehaviorSubject, combineLatest, of, timer} from '../web_modules/rxjs.js';
import {map, shareReplay, switchMap} from '../web_modules/rxjs/operators.js';
import { Injectable } from '../web_modules/@angular/core.js';
import { HttpClient } from '../web_modules/@angular/common/http.js';
import { MnPermissions } from './ajs.upgraded.providers.js';
import { MnAdminService } from './mn.admin.service.js';
import { MN_HTTP_REQUEST_RESTRICTED } from './constants/constants.js';

export { MnServerGroupsService }

class MnServerGroupsService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    HttpClient,
    MnAdminService,
    MnPermissions
  ]}

  constructor(http, mnAdminService, mnPermissions) {
    this.http = http;
    let permissions = mnPermissions.stream;

    this.stream = {};

    let getServerGroups =
      (new BehaviorSubject()).pipe(
        switchMap(this.getServerGroups.bind(this)));

    this.stream.shouldGetServerGroups =
      combineLatest(timer(0, 10000),
                    mnAdminService.stream.isGroupsAvailable,
                    permissions)
      .pipe(switchMap(([, isGroupsAvailable, permissions]) =>
          isGroupsAvailable && permissions.cluster.server_groups.read ?
            getServerGroups : of(MN_HTTP_REQUEST_RESTRICTED)),
        shareReplay({refCount: true, bufferSize: 1}));

    this.stream.nodesWithGroupName =
      combineLatest(this.stream.shouldGetServerGroups,
                    mnAdminService.stream.getNodes)
      .pipe(map(this.addGroupNameToNodes.bind(this)));
  }

  getServerGroups() {
    return this.http.get("/pools/default/serverGroups");
  }

  addGroupNameToNodes([groups, nodes]) {
    if (groups === MN_HTTP_REQUEST_RESTRICTED) {
      return nodes;
    }

    let nodesMap = {};

    groups.groups.forEach(group => group.nodes.forEach(node => nodesMap[node.otpNode] = group.name));
    nodes.forEach(node => node.groupName = nodesMap[node.otpNode]);

    return nodes;
  }
}
