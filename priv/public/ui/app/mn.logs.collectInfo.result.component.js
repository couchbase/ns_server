/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import {ChangeDetectionStrategy, Component} from '/ui/web_modules/@angular/core.js';
import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnLogsCollectInfoService} from './mn.logs.collectInfo.service.js';
import {MnAdminService} from './mn.admin.service.js';
import {UIRouter} from '/ui/web_modules/@uirouter/angular.js';
import {MnTasksService} from './mn.tasks.service.js';
import {switchMap, filter} from "../web_modules/rxjs/operators.js";

export { MnLogsCollectInfoResultComponent };

class MnLogsCollectInfoResultComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-logs-collect-info-result",
      templateUrl: "/ui/app/mn.logs.collectInfo.result.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnLogsCollectInfoService,
    MnAdminService,
    UIRouter,
    MnTasksService
  ]}

  constructor(mnLogsCollectInfoService, mnAdminService, uiRouter, mnTasksService) {
    super();

    this.mnLogsCollectInfoService = mnLogsCollectInfoService;
    this.uiRouter = uiRouter;

    this.postCancelLogsCollection = mnLogsCollectInfoService.stream.postCancelLogsCollection;
    this.taskCollectInfo = mnTasksService.stream.taskCollectInfo;
    this.nodes = mnAdminService.stream.getNodes;
    this.nodesByStatus = mnLogsCollectInfoService.stream.nodesByCollectInfoStatus;
    this.nodesErrors = mnLogsCollectInfoService.stream.nodesErrors;

    this.disableStopCollection = this.postCancelLogsCollection.success
      .pipe(switchMap(() => this.taskCollectInfo),
            filter(taskCollectInfo => taskCollectInfo.status === 'running'));
  }

  identifyNode(index, node) {
    return node.nodeName;
  }

  identifyNodeError(index, nodeError) {
    return nodeError.key;
  }

  startNewCollection() {
    this.uiRouter.stateService.go('app.admin.logs.collectInfo.form');
  }

  stopCollection() {
    this.mnLogsCollectInfoService.cancelLogsCollection();
  }
}
