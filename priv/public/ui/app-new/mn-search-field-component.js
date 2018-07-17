var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnSearchField =
  (function () {
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
        .takeUntil(this.mnOnDestroy)
        .subscribe(this.onInit.bind(this));
    }

    function onInit() {
      this.onClearClick = new Rx.Subject();
      this.mnFocusStream = this.mnFocusStream || Rx.Observable.never();
      this.mnClearStream = this.mnClearStream || Rx.Observable.never();

      this.onClearClick
        .merge(this.mnClearStream)
        .takeUntil(this.mnOnDestroy)
        .subscribe(this.clearSearchTerm.bind(this));

      this.isSearchPresent =
        this.mnFormGroup.valueChanges
        .pluck("searchTerm")
        .map(Boolean)
        .shareReplay(1);

    }

    function clearSearchTerm() {
      this.mnFormGroup.patchValue({searchTerm: ""});
    }
  })();
