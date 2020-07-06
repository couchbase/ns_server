import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js"
import {takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {Subject} from "/ui/web_modules/rxjs.js";
import {UIRouter} from "/ui/web_modules/@uirouter/angular.js";
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream, DetailsHashObserver} from './mn.core.js';

import {MnXDCRAddRefComponent} from "./mn.xdcr.add.ref.component.js";
import {MnXDCRDeleteRefComponent} from "./mn.xdcr.delete.ref.component.js";

export {MnXDCRRefItemComponent};

class MnXDCRRefItemComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-ref-item",
      templateUrl: "/ui/app/mn.xdcr.ref.item.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item"
      ]
    })
  ]}

  static get parameters() { return [
    MnPermissions,
    NgbModal,
    UIRouter
  ]}

  constructor(mnPermissions, modalService, uiRouter) {
    super();

    var onAddReference = new Subject();
    onAddReference
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(item => {
        var ref = modalService.open(MnXDCRAddRefComponent);
        ref.componentInstance.item = item;
      });

    var onDeleteReference = new Subject();
    onDeleteReference
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(function (item) {
        var ref = modalService.open(MnXDCRDeleteRefComponent);
        ref.componentInstance.item = item;
      });

    this.uiRouter = uiRouter;
    this.permissions = mnPermissions.export;
    this.onAddReference = onAddReference;
    this.onDeleteReference = onDeleteReference;
  }

  ngOnInit() {
    this.detailsHashObserver =
      new DetailsHashObserver(this.uiRouter, this, "xdcrDetails", this.item.name);
  }

  generateStatisticsLink(row) {
    return window.location.protocol + '//' +
      row.hostname + '/index.html#/analytics/?statsHostname=' +
      (encodeURIComponent(row.hostname))
  }
}
