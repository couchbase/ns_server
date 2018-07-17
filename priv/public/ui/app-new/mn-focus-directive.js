var mn = mn || {};
mn.directives = mn.directives || {};
mn.directives.MnFocus =
  (function () {
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

      this.mnOnInit
        .switchMap((function () {
          return this.mnFocus;
        }).bind(this))
        .filter(function (value) {
          if (typeof value === "string") {
            return value === elementName;
          } else {
            return value; //Boolean
          }
        })
        .takeUntil(this.mnOnDestroy)
        .subscribe(function (value) {
          el.nativeElement.focus();
        });
    }
  })();
