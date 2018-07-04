var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnBucketsItem =
  (function () {
    "use strict";

    mn.helper.extends(MnBucketsItem, mn.helper.MnEventableComponent);

    MnBucketsItem.annotations = [
      new ng.core.Component({
        selector: "mn-buckets-item",
        templateUrl: "app-new/mn-buckets-item.html",
        inputs: [
          "bucket"
        ]
      })
    ];

    MnBucketsItem.parameters = [
      mn.services.MnAdmin,
      mn.services.MnBuckets,
      mn.services.MnPermissions,
      mn.services.MnTasks,
      window['@uirouter/angular'].UIRouter
    ];

    MnBucketsItem.prototype.getNodesCountByStatusMessage = getNodesCountByStatusMessage;
    MnBucketsItem.prototype.addStatusMessagePart = addStatusMessagePart;
    MnBucketsItem.prototype.getResidentRatio = getResidentRatio;
    MnBucketsItem.prototype.getNodesCountByStatus = getNodesCountByStatus;
    MnBucketsItem.prototype.getNodesStatusClass = getNodesStatusClass;
    MnBucketsItem.prototype.getWarmUpProgress = getWarmUpProgress;

    return MnBucketsItem;

    function MnBucketsItem(mnAdminService, mnBucketsService, mnPermissionsService, mnTasksService, uiRouter) {
      mn.helper.MnEventableComponent.call(this);

      var bucketCurrentValue = this.mnOnChanges.pluck("bucket", "currentValue");
      var bucketNodes = bucketCurrentValue.pluck("nodes");
      var bucketName = bucketCurrentValue.pluck("name");

      this.compatVersion = mnAdminService.stream.compatVersion;
      this.statusClass = bucketNodes.map(this.getNodesStatusClass.bind(this));
      this.residentRatio = bucketCurrentValue.map(this.getResidentRatio.bind(this));

      this.detailsHashObserver =
        new mn.helper.DetailsHashObserver(
          uiRouter,
          "app.admin.buckets",
          "openedBuckets",
          this.mnOnDestroy,
          bucketName
        );

      this.bucketDataRead =
        mnPermissionsService.createPermissionStream("data!read", bucketName);
      this.bucketSettingsRead =
        mnPermissionsService.createPermissionStream("settings!read", bucketName);
      this.statsRead =
        mnPermissionsService.createPermissionStream("stats!read");
      this.tasksRead =
        mnPermissionsService.createPermissionStream("tasks!read");

      this.nodesCountByStatusMessage =
        bucketNodes
        .map(this.getNodesCountByStatus.bind(this))
        .map(this.getNodesCountByStatusMessage.bind(this));

      this.warmUpProgress =
        mnTasksService
        .stream
        .tasksWarmingUp
        .withLatestFrom(bucketCurrentValue)
        .map(this.getWarmUpProgress.bind(this));

    }

    function getNodesCountByStatusMessage(nodesByStatuses) {
      return _.map(nodesByStatuses, function (count, status) {
        return count + ' node' + (count !== 1 ? "s" : "") + ' ' + status;
      });
    }

    function addStatusMessagePart(status, message) {
      if (status.length) {
        return status + ", " + message;
      } else {
        return status + message;
      }
    }

    function getResidentRatio(bucket) {
      var items = bucket.basicStats.itemCount;
      var activeResident = bucket.basicStats.vbActiveNumNonResident;
      if (items === 0) {
        return 100;
      }
      if (items < activeResident) {
        return 0;
      }
      return (items - activeResident) * 100 / items;
    }

    function getNodesCountByStatus(nodes) {
      var nodesByStatuses = {};

      _.forEach(nodes, function (node) {
        var status = "";

        if (node.clusterMembership === 'inactiveFailed') {
          status = addStatusMessagePart(status, "failed over");
        }
        if (node.status === 'unhealthy') {
          status = addStatusMessagePart(status, "not responding");
        }
        if (node.status === 'warmup') {
          status = addStatusMessagePart(status, "pending");
        }
        if (status != "") {
          nodesByStatuses[status] = ++nodesByStatuses[status] || 1;
        }
      });

      return nodesByStatuses;
    }

    function getNodesStatusClass(nodes) {
      var statusClass = nodes.length ? "healthy" : "inactive";

      for (var i = 0; i < nodes.length; i++) {
        if (nodes[i].status === "unhealthy") {
          statusClass = nodes[i].status;
          break;
        }
        if (statusClass !== "inactiveFailed" && nodes[i].status === "warmup") {
          statusClass = nodes[i].status;
        }
        if (nodes[i].clusterMembership === "inactiveFailed") {
          statusClass = nodes[i].clusterMembership;
        }
      }

      return ("dynamic_" + statusClass);
    }

    function getWarmUpProgress(values) {
      var bucket = values[1];
      var tasks = values[0];
      if (!bucket || !tasks) {
        return false;
      }
      var totalPercent = 0;
      var exists = false;

      tasks.forEach(function (task) {
        if (task.bucket === bucket.name) {
          exists = true;
          if (!(Number(task.stats.ep_warmup_estimated_key_count) ||
                Number(task.stats.ep_warmup_estimated_value_count))) {
            return;
          }
          switch (task.stats.ep_warmup_state) {
          case "loading keys":
            totalPercent += (Number(task.stats.ep_warmup_key_count) /
                             Number(task.stats.ep_warmup_estimated_key_count) * 100);
            break;
          case "loading data":
            totalPercent += (Number(task.stats.ep_warmup_value_count) /
                             Number(task.stats.ep_warmup_estimated_value_count) * 100);
            break;
          default:
            return 100;
          }
        }
      });

      return exists ? (totalPercent / bucket.nodes.length) : false;
    }

  })();
