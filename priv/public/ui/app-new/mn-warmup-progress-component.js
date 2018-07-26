var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnWarmupProgress =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnWarmupProgressComponent, mn.helper.MnEventableComponent);

    MnWarmupProgressComponent.annotations = [
      new ng.core.Component({
        selector: "mn-warmup-progress",
        templateUrl: "app-new/mn-warmup-progress.html",
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

      var tasksCurrentValue = this.mnOnChanges.pipe(Rx.operators.switchMap(this.getTasks.bind(this)));

      this.tasks =
        Rx.combineLatest(
          tasksCurrentValue,
          this.limitTo
        ).pipe(
          Rx.operators.map(this.slice),
          Rx.operators.map(this.sortBy.bind(this))
        );

      this.isTasksLessThanLimit =
        tasksCurrentValue.pipe(Rx.operators.map(this.isLessThanLimit.bind(this)));

      this.toggleText =
        this.limitTo.pipe(Rx.operators.map(toggleText));

      this.onToggle
        .pipe(
          Rx.operators.tap(this.stopPropagation),
          Rx.operators.withLatestFrom(this.limitTo),
          Rx.operators.map(this.toggle.bind(this)),
          Rx.operators.takeUntil(this.mnOnDestroy)
        )
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

  })(window.rxjs);
