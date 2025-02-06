/*
Copyright 2021-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/
import _ from 'lodash';
import { MnTasksService } from '../mn.tasks.service.js';
import axios from 'axios';

// Add cache variable at the top level
const httpCache = new Map();

function mnTasksDetailsFactory(mnTasksService) {
  var mnTasksDetails = {
    get: get,
    clearCache: clearCache,
    getFresh: getFresh,
    getRebalanceReport: getRebalanceReport,
    clearRebalanceReportCache: clearRebalanceReportCache,
  };

  return mnTasksDetails;

  function getRebalanceReport(url) {
    const reportUrl = url || '/logs/rebalanceReport';
    // Check cache first
    if (httpCache.has(reportUrl)) {
      return Promise.resolve(httpCache.get(reportUrl));
    }

    return axios({
      url: reportUrl,
      method: 'GET',
    }).then(
      function (response) {
        httpCache.set(reportUrl, response);
        return response;
      },
      function () {
        return { data: { stageInfo: {} } };
      }
    );
  }

  function clearRebalanceReportCache(url) {
    httpCache.delete(url || '/logs/rebalanceReport');
    return this;
  }

  function get(mnHttpParams) {
    const tasksUrl = '/pools/default/tasks';
    // Check cache first
    if (httpCache.has(tasksUrl)) {
      return Promise.resolve(httpCache.get(tasksUrl));
    }

    return axios({
      url: tasksUrl,
      method: 'GET',
      mnHttp: mnHttpParams,
    }).then(function (resp) {
      var rv = {};
      var tasks = resp.data;

      rv.tasks = tasks;
      rv.tasksXDCR = _.filter(tasks, detectXDCRTask);
      rv.tasksCollectInfo = _.filter(tasks, detectCollectInfoTask);
      rv.tasksRecovery = _.detect(tasks, detectRecoveryTasks);
      rv.tasksRebalance = _.detect(tasks, detectRebalanceTasks);
      rv.tasksWarmingUp = _.filter(tasks, detectWarmupTask);
      rv.tasksBucketCompaction = _.filter(tasks, detectBucketCompactionTask);
      rv.tasksViewCompaction = _.filter(tasks, detectViewCompactionTask);
      rv.inRebalance = !!(
        rv.tasksRebalance && rv.tasksRebalance.status === 'running'
      );
      rv.inRecoveryMode = !!rv.tasksRecovery;
      rv.loadingSamples = _.filter(tasks, detectLoadingSamples);
      rv.isLoadingSamples = !!_.detect(tasks, detectLoadingSamples);
      rv.stopRecoveryURI = rv.tasksRecovery && rv.tasksRecovery.stopURI;
      rv.isSubtypeFailover = !!(
        rv.tasksRebalance &&
        ['gracefulFailover', 'failover'].includes(rv.tasksRebalance.subtype)
      );
      rv.running = _.filter(tasks, function (task) {
        return task.status === 'running';
      });
      rv.isOrphanBucketTask = !!_.detect(tasks, detectOrphanBucketTask);

      mnTasksService.stream.tasksXDCRPlug.next(rv.tasksXDCR);
      mnTasksService.stream.tasksWarmingUpPlug.next(rv.tasksWarmingUp);
      mnTasksService.stream.tasksBucketCompactionPlug.next(
        rv.tasksBucketCompaction
      );
      mnTasksService.stream.tasksViewCompactionPlug.next(
        rv.tasksViewCompaction
      );
      mnTasksService.stream.tasksLoadingSamples.next(rv.loadingSamples);

      let noCollectInfoTask = {
        nodesByStatus: {},
        nodeErrors: [],
        status: 'idle',
        perNode: {},
      };
      mnTasksService.stream.taskCollectInfoPlug.next(
        rv.tasksCollectInfo[0] || noCollectInfoTask
      );
      // Cache the response
      httpCache.set(tasksUrl, rv);
      return rv;
    });
  }

  function detectXDCRTask(taskInfo) {
    return taskInfo.type === 'xdcr';
  }

  function detectCollectInfoTask(taskInfo) {
    return taskInfo.type === 'clusterLogsCollection';
  }

  function detectOrphanBucketTask(taskInfo) {
    return taskInfo.type === 'orphanBucket';
  }

  function detectRecoveryTasks(taskInfo) {
    return taskInfo.type === 'recovery';
  }

  function detectRebalanceTasks(taskInfo) {
    return taskInfo.type === 'rebalance';
  }

  function detectLoadingSamples(taskInfo) {
    return (
      taskInfo.type === 'loadingSampleBucket' && taskInfo.status === 'running'
    );
  }

  function detectWarmupTask(taskInfo) {
    return taskInfo.type === 'warming_up' && taskInfo.status === 'running';
  }

  function detectBucketCompactionTask(taskInfo) {
    return taskInfo.type === 'bucket_compaction';
  }

  function detectViewCompactionTask(taskInfo) {
    return taskInfo.type === 'view_compaction' || taskInfo.type === 'indexer';
  }

  function clearCache() {
    httpCache.delete('/pools/default/tasks');
    return this;
  }

  function getFresh(mnHttpParams) {
    return mnTasksDetails.clearCache().get(mnHttpParams);
  }
}

const mnTasksDetails = mnTasksDetailsFactory(MnTasksService);
export default mnTasksDetails;
