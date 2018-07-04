var mn = mn || {};
mn.components = mn.components || {};
mn.components.MnBarUsage =
  (function () {
    "use strict";

    MnBarUsageComponent.annotations = [
      new ng.core.Component({
        selector: "mn-bar-usage",
        templateUrl: "app-new/mn-bar-usage.html",
        inputs: [
          "baseInfo",
          "total"
        ],
      })
    ];

    return MnBarUsageComponent;

    function MnBarUsageComponent() {}
  })();
