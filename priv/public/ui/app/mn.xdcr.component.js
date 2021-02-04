import {Component, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js';
import {combineLatest, Subject, timer, BehaviorSubject} from "/ui/web_modules/rxjs.js";
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js";
import {takeUntil} from '/ui/web_modules/rxjs/operators.js';
import {MnPermissions} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnXDCRService} from './mn.xdcr.service.js';
import {MnPoolsService} from './mn.pools.service.js';
import {MnTasksService} from './mn.tasks.service.js';
import {MnHelperService} from './mn.helper.service.js';

import {MnXDCRAddRefComponent} from "./mn.xdcr.add.ref.component.js";

export { MnXDCRComponent };

class MnXDCRComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      templateUrl: "/ui/app/mn.xdcr.html",
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    MnPermissions,
    MnXDCRService,
    MnPoolsService,
    MnTasksService,
    MnHelperService,
    NgbModal
  ]}

  constructor(mnPermissions, mnXDCRService, mnPoolsService, mnTasksService,
              mnHelperService, modalService) {
    super();

    var onAddReference = new Subject();
    onAddReference
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(() => modalService.open(MnXDCRAddRefComponent));

    var referenceSorter = mnHelperService.createSorter("name");

    this.tasksXDCR = mnTasksService.stream.tasksXDCR;
    this.isEnterprise = mnPoolsService.stream.isEnterprise;

    this.permissions = mnPermissions.stream;
    this.references = mnXDCRService.stream.getRemoteClustersFiltered
      .pipe(referenceSorter.pipe);

    this.onAddReference = onAddReference;
    this.referenceSorter = referenceSorter;

    this.getChangesLeftTotal = mnXDCRService.stream.getChangesLeftTotal;

  }

  trackByFn(_, row) {
    return row.name;
  }

  tasksTrackByFn(_, row) {
    return row.id;
  }
}
