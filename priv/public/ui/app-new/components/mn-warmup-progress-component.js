var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnWarmupProgress =
  (function () {
    "use strict";

    mn.helper.extends(MnWarmupProgressComponent, mn.helper.MnEventableComponent);

    MnWarmupProgressComponent.annotations = [
      new ng.core.Component({
        selector: "mn-warmup-progress",
        templateUrl: "app-new/components/mn-warmup-progress.html",
        inputs: [
          "mnTasks", //observable
          "mnSortBy" //string
        ]
      })
    ];

    MnWarmupProgressComponent.prototype.stopPropagation = stopPropagation;
    MnWarmupProgressComponent.prototype.sortBy = sortBy;
    MnWarmupProgressComponent.prototype.slice = slice;
    MnWarmupProgressComponent.prototype.toggle = toggle;
    MnWarmupProgressComponent.prototype.toggleText = toggleText;
    MnWarmupProgressComponent.prototype.isLessThanLimit = isLessThanLimit;
    MnWarmupProgressComponent.prototype.getTasks = getTasks;

    return MnWarmupProgressComponent;

    function MnWarmupProgressComponent() {
      mn.helper.MnEventableComponent.call(this);

      this.limit = 3;
      this.onToggle = new Rx.Subject();
      this.limitTo = new Rx.BehaviorSubject(this.limit);

      var tasksCurrentValue = this.mnOnChanges.switchMap(this.getTasks.bind(this));

      this.tasks =
        tasksCurrentValue
        .combineLatest(this.limitTo)
        .map(this.slice)
        .map(this.sortBy.bind(this));

      this.isTasksLessThanLimit =
        tasksCurrentValue
        .map(this.isLessThanLimit.bind(this));

      this.toggleText =
        this.limitTo
        .map(toggleText);

      this.onToggle
        .do(this.stopPropagation)
        .withLatestFrom(this.limitTo)
        .map(this.toggle.bind(this))
        .takeUntil(this.mnOnDestroy)
        .subscribe(this.limitTo);
    }

    function getTasks() {
      return this.mnTasks;
    }

    function stopPropagation($event) {
      $event.stopPropagation();
    }

    function sortBy(tasks) {
      return _.sortBy(tasks, this.mnSortBy);
    }

    function slice(values) {
      return values[0].slice(0, values[1]);
    }

    function toggle(limit) {
      return !!limit[1] ? undefined : this.limit;
    }

    function toggleText(limit) {
      return !!limit ? '... more' : 'less';
    }

    function isLessThanLimit(tasks) {
      return tasks.length <= this.limit;
    }

  })();
