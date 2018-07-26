var mn = mn || {};
mn.directives = mn.directives || {};
mn.directives.MnFocus =
  (function (Rx) {
    "use strict";

    mn.helper.extends(MnFocusDirective, mn.helper.MnEventableComponent);

    MnFocusDirective.annotations = [
      new ng.core.Directive({
        selector: "[mnFocus]",
        inputs: [
          "mnFocus"
        ],
        host: {
          '(blur)': 'blur()'
        }
      })
    ];

    MnFocusDirective.parameters = [
      ng.core.ElementRef
    ];

    MnFocusDirective.prototype.blur = blur;

    return MnFocusDirective;

    function blur() {
      // this.mnFocus.next(false);
    }

    function MnFocusDirective(el) {
      mn.helper.MnEventableComponent.call(this);

      var elementName = el.nativeElement.getAttribute("formControlName");

      this.mnOnInit.pipe(
        Rx.operators.switchMap((function () {
          return this.mnFocus;
        }).bind(this)),
        Rx.operators.filter(function (value) {
          if (typeof value === "string") {
            return value === elementName;
          } else {
            return value; //Boolean
          }
        }),
        Rx.operators.takeUntil(this.mnOnDestroy)
      ).subscribe(function (value) {
        el.nativeElement.focus();
      });
    }
  })(window.rxjs);
