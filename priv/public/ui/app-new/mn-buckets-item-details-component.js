var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnBucketsItemDetails =
  (function () {
    "use strict";

    mn.helper.extends(MnBucketsItemDetails, mn.helper.MnEventableComponent);

    MnBucketsItemDetails.annotations = [
      new ng.core.Component({
        selector: "mn-buckets-item-details",
        templateUrl: "app-new/mn-buckets-item-details.html",
        inputs: [
          "bucket"
        ]
      })
    ];

    MnBucketsItemDetails.parameters = [
      mn.services.MnBuckets,
      mn.services.MnPermissions,
      mn.services.MnTasks,
      window['@uirouter/angular'].UIRouter,
      mn.services.MnAdmin,
      ngb.NgbModal
    ];

    MnBucketsItemDetails.prototype.getWarmUpTasks = getWarmUpTasks;
    MnBucketsItemDetails.prototype.getBucketRamGuageConfigParams = getBucketRamGuageConfigParams;
    MnBucketsItemDetails.prototype.getGuageConfig = getGuageConfig;

    return MnBucketsItemDetails;

    function MnBucketsItemDetails(mnBucketsService, mnPermissionsService, mnTasksService, uiRouter, mnAdminService, modalService) {
      mn.helper.MnEventableComponent.call(this);
      this.editButtonClickEvent = new Rx.Subject();
      this.isRebalancing = mnAdminService.stream.isRebalancing;

      var bucketCurrentValue = this.mnOnChanges.pluck("bucket", "currentValue");
      var bucketName = bucketCurrentValue.pluck("name");

      var thisBucketCompactionTask =
          bucketName
          .distinctUntilChanged()
          .combineLatest(mnTasksService.stream.tasksBucketCompaction)
          .map(function (values) {
            return _.find(values[1], function (task) {
              return task.bucket === values[0];
            });
          });

      this.editButtonClickEvent
        .takeUntil(this.mnOnDestroy)
        .subscribe(function (bucket) {
          var ref = modalService.open(mn.components.MnBucketsDialog);
          ref.componentInstance.bucket = bucket;
        });

      this.thisBucketCompactionProgress =
        thisBucketCompactionTask
        .map(function (task) {
          return task ? (task.progress + "% complete") : "Not active";
        });

      this.compatVersion = mnAdminService.stream.compatVersion;
      this.tasksRead = mnPermissionsService.createPermissionStream("tasks!read");

      this.warmUpTasks =
        mnTasksService.stream.tasksWarmingUp
        .withLatestFrom(bucketCurrentValue)
        .map(this.getWarmUpTasks.bind(this));

      this.bucketSettingsWrite =
        mnPermissionsService.createPermissionStream("settings!write", bucketName);

      this.bucketRamGuageConfig =
        bucketCurrentValue
        .map(this.getBucketRamGuageConfigParams.bind(this))
        .map(mnBucketsService.getBucketRamGuageConfig)

      this.bucketDiskGuageConfig =
        bucketCurrentValue
        .map(this.getGuageConfig.bind(this))
        .map(mnBucketsService.getGuageConfig)

    }

    function getWarmUpTasks(values) {
      var bucket = values[1];
      var tasks = values[0];
      if (!bucket || !tasks) {
        return;
      }
      return _.filter(tasks, function (task) {
        var isNeeded = task.bucket === bucket.name;
        if (isNeeded) {
          task.hostname = _.find(bucket.nodes, function (node) {
            return node.otpNode === task.node;
          }).hostname;
        }
        return isNeeded;
      });
    }

    function getBucketRamGuageConfigParams(details) {
      if (!details) {
        return;
      }
      return {
        total: details.basicStats.storageTotals.ram.quotaTotalPerNode * details.nodes.length,
        thisAlloc: details.quota.ram,
        otherBuckets: details.basicStats.storageTotals.ram.quotaUsedPerNode * details.nodes.length - details.quota.ram
      };
    }

    function getGuageConfig(details) {
      return {
        total: details.basicStats.storageTotals.hdd.total,
        thisBucket: details.basicStats.diskUsed,
        otherBuckets: details.basicStats.storageTotals.hdd.usedByData - details.basicStats.diskUsed,
        otherData: details.basicStats.storageTotals.hdd.used - details.basicStats.storageTotals.hdd.usedByData
      };
    }

  })();
