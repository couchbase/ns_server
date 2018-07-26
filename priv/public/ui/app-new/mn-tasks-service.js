var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnTasks = (function (Rx) {
  "use strict";

  MnTasksService.annotations = [
    new ng.core.Injectable()
  ];

  MnTasksService.parameters = [
    ng.common.http.HttpClient,
    mn.services.MnAdmin
  ];

  MnTasksService.prototype.get = get;

  return MnTasksService;

  function MnTasksService(http, mnAdminService) {
    this.http = http;
    this.stream = {};
    this.stream.interval = new Rx.Subject();

    var tasksTypesToDisplay = {
      indexer: true,
      rebalance: true,
      orphanBucket: true,
      global_indexes: true,
      view_compaction: true,
      bucket_compaction: true,
      loadingSampleBucket: true,
      clusterLogsCollection: true
    };

    var setupInterval =
        this.stream.interval.pipe(
          Rx.operators.startWith(0),
          Rx.operators.switchMap(function (interval) {
            return Rx.timer(interval);
          })
        );

    var getUrl =
        mnAdminService.stream.getPoolsDefault.pipe(
          Rx.operators.pluck("tasks", "uri"),
          Rx.operators.distinctUntilChanged()
        );

    this.stream.getSuccess =
      Rx.combineLatest(
        getUrl,
        setupInterval
      ).pipe(
        Rx.operators.switchMap(this.get.bind(this)),
        Rx.operators.publishReplay(1),
        Rx.operators.refCount()
      );

    var tasks = this.stream.getSuccess;

    this.stream.tasksWarmingUp =
      tasks.pipe(
        Rx.operators.map(function (tasks) {
          return _.filter(tasks, function (task) {
            return task.type === 'warming_up' && task.status === 'running';
          });
        })
      );

    this.stream.tasksBucketCompaction =
      tasks.pipe(
        Rx.operators.map(function (tasks) {
          return _.filter(tasks, function (task) {
            return task.type === 'bucket_compaction';
          });
        })
      );

    this.stream.extractNextInterval =
      this.stream.getSuccess.pipe(
        Rx.operators.map(function (tasks) {
          return (_.chain(tasks)
                  .pluck('recommendedRefreshPeriod')
                  .compact()
                  .min()
                  .value() * 1000) >> 0 || 10000;
        })
      );

    this.stream.running =
      this.stream.getSuccess.pipe(
        Rx.operators.map(_.curry(_.filter)(_, function (task) {
          return task.status === "running";
        }))
      );

    this.stream.tasksToDisplay =
      this.stream.running.pipe(
        Rx.operators.map(_.curry(_.filter)(_, function (task) {
          return tasksTypesToDisplay[task.type];
        }))
      );

  }

  function get(url) {
    return this.http.get(url[0]);
  }

})(window.rxjs);
