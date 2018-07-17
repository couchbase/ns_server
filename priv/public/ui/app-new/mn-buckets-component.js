var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnBuckets =
  (function () {
    "use strict";

    mn.helper.extends(MnBuckets, mn.helper.MnEventableComponent);

    MnBuckets.annotations = [
      new ng.core.Component({
        templateUrl: "app-new/mn-buckets.html"
      })
    ];

    MnBuckets.parameters = [
      // window['@uirouter/angular'].UIRouter,
      mn.services.MnAdmin,
      mn.services.MnBuckets,
      mn.services.MnPermissions,
      ngb.NgbModal
    ];

    MnBuckets.prototype.trackByFn = trackByFn;

    return MnBuckets;

    function trackByFn(_, bucket) {
      return bucket.name;
    }

    function MnBuckets(mnAdminService, mnBucketsService, mnPermissionsService, modalService) {
      mn.helper.MnEventableComponent.call(this);

      this.isRebalancing = mnAdminService.stream.isRebalancing;
      this.maxBucketCount = mnAdminService.stream.maxBucketCount;
      this.onAddBucketClick = new Rx.Subject();
      this.onSortByClick = new Rx.BehaviorSubject("name");

      this.buckets =
        mnBucketsService.stream.bucketsWithTimer
        .let(mn.helper.sortByStream(this.onSortByClick));

      this.maybeShowMaxBucketCountWarning =
        mnAdminService
        .stream
        .maxBucketCount
        .combineLatest(this.buckets)
        .map(function (rv) {
          return rv[1].length >= rv[0];
        });

      this.maybeShowAddBucketBuctton =
        this.maybeShowMaxBucketCountWarning
        .combineLatest(this.isRebalancing,
                       mnPermissionsService.createPermissionStream("buckets!create"))
        .map(function (rv) {
          return !rv[0] && !rv[1] && rv[2];
        });

      this.onAddBucketClick
        .takeUntil(this.mnOnDestroy)
        .subscribe(function (rv) {
          var ref = modalService.open(mn.components.MnBucketsDialog);
          ref.componentInstance.bucket = null;
        });
    }

  })();
