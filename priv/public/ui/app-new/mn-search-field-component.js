var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnSearchField =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnSearchFieldComponent, mn.helper.MnEventableComponent);

    MnSearchFieldComponent.annotations = [
      new ng.core.Component({
        selector: "mn-search-field",
        templateUrl: 'app-new/mn-search-field.html',
        inputs: [
          "mnFormGroup",
          "mnFocusStream",
          "mnClearStream",
          "mnPlaceholder"
        ]
      })
    ];

    MnSearchFieldComponent.prototype.clearSearchTerm = clearSearchTerm;
    MnSearchFieldComponent.prototype.onInit = onInit;

    return MnSearchFieldComponent;

    function MnSearchFieldComponent() {
      mn.helper.MnEventableComponent.call(this);

      this.mnOnInit
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.onInit.bind(this));
    }

    function onInit() {
      this.onClearClick = new Rx.Subject();
      this.mnFocusStream = this.mnFocusStream || Rx.Observable.never();
      this.mnClearStream = this.mnClearStream || Rx.Observable.never();

      Rx.merge(this.onClearClick, this.mnClearStream)
        .pipe(Rx.operators.takeUntil(this.mnOnDestroy))
        .subscribe(this.clearSearchTerm.bind(this));

      this.isSearchPresent =
        this.mnFormGroup.valueChanges.pipe(
          Rx.operators.pluck("searchTerm"),
          Rx.operators.map(Boolean),
          Rx.operators.shareReplay(1)
        );

    }

    function clearSearchTerm() {
      this.mnFormGroup.patchValue({searchTerm: ""});
    }
  })(window.rxjs);
