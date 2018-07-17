var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnSearch =
  (function () {
    "use strict";

    MnSearchComponent.annotations = [
      new ng.core.Component({
        selector: "mn-search",
        templateUrl: 'app-new/mn-search.html',
        inputs: [
          "mnFormGroup",
          "mnPlaceholder"
        ]
      })
    ];

    return MnSearchComponent;

    function MnSearchComponent() {
      this.onShowClick = new Rx.Subject();
      this.onHideClick = new Rx.Subject();

      var showToTrue = this.onShowClick.mapTo(true);
      var hideToFalse = this.onHideClick.mapTo(false);

      this.toggleFilter =
        showToTrue
        .merge(hideToFalse)
        .shareReplay(1);//do not calculate toggleFilter on each subscription

      this.mnFocusStream =
        showToTrue
        .debounceTime(0);//wait until field will be shown in order to do focus
    }
  })();
