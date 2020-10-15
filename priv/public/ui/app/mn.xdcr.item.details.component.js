import {Component, Pipe, ChangeDetectionStrategy} from '/ui/web_modules/@angular/core.js'
import {NgbModal} from "/ui/web_modules/@ng-bootstrap/ng-bootstrap.js"
import {Subject, pipe} from "/ui/web_modules/rxjs.js";
import {pluck, map, shareReplay, takeUntil,
        withLatestFrom, filter} from '/ui/web_modules/rxjs/operators.js';
import {MnPermissions, $rootScope} from '/ui/app/ajs.upgraded.providers.js';

import {MnLifeCycleHooksToStream} from './mn.core.js';
import {MnXDCRService} from './mn.xdcr.service.js';
import {MnFormService} from "./mn.form.service.js";
import {MnXDCRDeleteRepComponent} from "./mn.xdcr.delete.rep.component.js";

export {MnXDCRItemDetailsComponent, MnReplicationStatus};

class MnXDCRItemDetailsComponent extends MnLifeCycleHooksToStream {
  static get annotations() { return [
    new Component({
      selector: "mn-xdcr-item-details",
      templateUrl: "app/mn.xdcr.item.details.html",
      changeDetection: ChangeDetectionStrategy.OnPush,
      inputs: [
        "item"
      ]
    })
  ]}

  static get parameters() { return [
    MnPermissions,
    MnXDCRService,
    MnFormService,
    NgbModal,
    $rootScope
  ]}

  constructor(mnPermissions, mnXDCRService, mnFormService, modalService, $rootScope) {
    super();

    this.mnFormService = mnFormService;
    this.mnXDCRService = mnXDCRService;
    this.$rootScope = $rootScope;

    var onDeleteReplication = new Subject();
    onDeleteReplication
      .pipe(takeUntil(this.mnOnDestroy))
      .subscribe(item => {
        var ref = modalService.open(MnXDCRDeleteRepComponent);
        ref.componentInstance.item = item;
      });

    this.permissions = mnPermissions.export;
    this.onDeleteReplication = onDeleteReplication;

  }

  ngOnInit() {
    var form = this.mnFormService.create(this);
    var itemStream = this.mnOnChanges.pipe(pluck("item", "currentValue"));
    var status = itemStream.pipe(map(this.getStatus),
                                 shareReplay({refCount: true, bufferSize: 1}));
    form
      .setFormGroup({})
      .setPackPipe(pipe(withLatestFrom(status),
                        filter(([_, status]) => status !== "spinner"),
                        map(([item, _]) => [item.id, {
                          pauseRequested: item.status !== "paused"
                        }])))
      .setPostRequest(this.mnXDCRService.stream.postPausePlayReplication)
      .success(() => this.$rootScope.$broadcast("reloadTasksPoller"));

    this.form = form;
    this.status = status;
    this.statusClass = status.pipe(map(v => "fa-" + v));
  }

  getStatus(row) {
    if (row.pauseRequested && row.status != 'paused') {
      return 'spinner';
    } else {
      switch (row.status) {
      case 'running': return 'pause';
      case 'paused': return 'play';
      default: return 'spinner';
      }
    }
  }
}

class MnReplicationStatus {
  static get annotations() { return [
    new Pipe({name: "mnReplicationStatus"})
  ]}

  transform(status) {
    switch (status) {
    case "spinner": return "Pausing";
    case "pause": return "Pause";
    case "play": return "Run";
    }
  }
}
