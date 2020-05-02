import {NgModule,
        Injectable,
        Component,
        ChangeDetectionStrategy,
        ElementRef,
        Renderer2} from "/ui/web_modules/@angular/core.js";

export {MnElementCraneModule,
        MnElementCraneService,
        MnElementCargoComponent,
        MnElementDepotComponent};

class MnElementCraneService {
  static get annotations() { return [
    new Injectable()
  ]}

  constructor() {
    this.depots = {};
  }

  register(element, name) {
    this.depots[name] = element;
  }

  unregister(name) {
    delete this.depots[name];
  }

  get(name) {
    return this.depots[name];
  }
}

class MnElementCargoComponent {
  static get annotations() { return [
    new Component({
      selector: "mn-element-cargo",
      template: "<ng-content></ng-content>",
      inputs: [
        "depot"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    ElementRef,
    Renderer2,
    MnElementCraneService
  ]}

  constructor(el, renderer2, mnElementCraneService) {
    this.el = el;
    this.renderer = renderer2;
    this.mnElementCraneService = mnElementCraneService;
  }

  ngOnInit() {
    this.depotElement = this.mnElementCraneService.get(this.depot);
    this.renderer.appendChild(this.depotElement.nativeElement, this.el.nativeElement);
  }

  ngOnDestroy() {
    this.renderer.removeChild(this.depotElement.nativeElement, this.el.nativeElement);
  }
}

class MnElementDepotComponent {
  static get annotations() { return [
    new Component({
      selector: "mn-element-depot",
      template: "<ng-content></ng-content>",
      inputs: [
        "name"
      ],
      changeDetection: ChangeDetectionStrategy.OnPush
    })
  ]}

  static get parameters() { return [
    ElementRef,
    MnElementCraneService
  ]}

  constructor(el, mnElementCraneService) {
    this.el = el;
    this.mnElementCraneService = mnElementCraneService;
  }

  ngOnInit() {
    this.mnElementCraneService.register(this.el, this.name);
  }

  ngOnDestroy() {
    this.mnElementCraneService.unregister(this.name);
  }
}

class MnElementCraneModule {
  static forRoot() {
    return {
      ngModule: MnElementCraneModule,
      providers: [MnElementCraneService]
    };
  }

  static get annotations() { return [
    new NgModule({
      declarations: [
        MnElementDepotComponent,
        MnElementCargoComponent
      ],
      exports: [
        MnElementDepotComponent,
        MnElementCargoComponent
      ],
      entryComponents: [
        MnElementCargoComponent,
        MnElementDepotComponent
      ],
    })
  ]}
}
