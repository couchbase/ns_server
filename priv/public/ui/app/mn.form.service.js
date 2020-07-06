import { MnAlertsService } from '/ui/app/ajs.upgraded.providers.js';
import { Injectable } from '/ui/web_modules/@angular/core.js';
import { FormBuilder, FormGroup } from '/ui/web_modules/@angular/forms.js';
import { BehaviorSubject, Subject, NEVER, merge } from "/ui/web_modules/rxjs.js";
import { map, tap, first, takeUntil, switchMap, mapTo,
         throttleTime, shareReplay } from "/ui/web_modules/rxjs/operators.js";


export { MnFormService };

class MnFormService {
  static get annotations() { return [
    new Injectable()
  ]}

  static get parameters() { return [
    FormBuilder,
    MnAlertsService
    // ngb.NgbModal
  ]}

  constructor(formBuilder, mnAlertsService, modalService) {
    this.formBuilder = formBuilder;
    this.mnAlertsService = mnAlertsService;
    this.modalService = modalService;
  }

  create(component) {
    return new MnForm(this.formBuilder, component, this.mnAlertsService);
  }
}

class MnForm {
  constructor(builder, component, mnAlertsService) {
    this.builder = builder;
    this.component = component;
    this.mnAlertsService = mnAlertsService;
    this.defaultPackPipe = map(this.getFormValue.bind(this));
    this.requestsChain = [];
  }

  getFormValue() {
    return this.group.value;
  }

  setFormGroup(formDescription) {
    this.group = (formDescription instanceof FormGroup) ?
      formDescription : this.builder.group(formDescription);
    return this;
  }

  setSource(source) {
    var sourcePipe = source.pipe(this.unpackPipe || tap(), first());

    sourcePipe.subscribe(v => this.group.patchValue(v));

    return this;
  }

  getLastRequest() {
    return this.requestsChain[this.requestsChain.length - 1];
  }

  success(fn) {
    (this.requestsChain.length ? this.getLastRequest().success : this.submitPipe)
      .pipe(takeUntil(this.component.mnOnDestroy))
      .subscribe(fn);
    return this;
  }

  error(fn) {
    this.getLastRequest().error
      .pipe(this.unpackErrorPipe || tap(),
            takeUntil(this.component.mnOnDestroy))
      .subscribe(fn);
    return this;
  }

  successMessage(message) {
    this.success(() => this.mnAlertsService.formatAndSetAlerts(message, "success", 2500));
    return this;
  }

  errorMessage(message) {
    this.error(() => this.mnAlertsService.formatAndSetAlerts(message, "error"));
    return this;
  }

  disableFields(path) {
    return (value) => {
      this.group.get(path)[value ? "disable" : "enable"]({emitEvent: false});
    }
  }

  trackSubmit() {
    var response = this.getLastRequest().response.pipe(mapTo(false));
    var request = this.submit.pipe(mapTo(true));
    this.processing = merge(request, response).pipe(shareReplay({refCount: true, bufferSize: 1}));
    return this;
  }

  setPostRequest(postRequest) {
    let lastRequest = this.getLastRequest();
    this.requestsChain.push(postRequest);

    if (!lastRequest) {
      this.createSubmitPipe();
      this.submitPipe.subscribe((v) => this.requestsChain[0].post(v));
    } else {
      lastRequest.success
        .pipe(this.getPackPipe(),
              takeUntil(this.component.mnOnDestroy))
        .subscribe((function (postRequestIndex) {
          return (v) => this.requestsChain[postRequestIndex - 1].post(v);
        }.bind(this))(this.requestsChain.length));
    }
    return this;
  }

  hasNoPostRequest() {
    this.createSubmitPipe();
    return this;
  }

  getPackPipe() {
    return this.packPipe || (this.group ? this.defaultPackPipe : tap())
  }

  createSubmitPipe() {
    this.submit = new Subject();
    this.submitPipe =
      this.submit.pipe(this.getPackPipe(),
                       takeUntil(this.component.mnOnDestroy))
  }

  hasNoHandler() {
    this.getLastRequest().success
      .pipe(takeUntil(this.component.mnOnDestroy))
      .subscribe();
    return this;
  }

  clearErrors() {
    this.submit
      .pipe(takeUntil(this.component.mnOnDestroy))
      .subscribe(() => this.requestsChain.forEach((req) => req.clearError()));
    return this;
  }

  setUnpackErrorPipe(unpackErrorPipe) {
    this.unpackErrorPipe = unpackErrorPipe;
    return this
  }

  setUnpackPipe(unpackPipe) {
    this.unpackPipe = unpackPipe;
    return this;
  }

  setPackPipe(packPipe) {
    this.packPipe = packPipe;
    return this;
  }

  confirmation504(dialog) {
    this.getLastRequest().error
      .pipe(takeUntil(this.component.mnOnDestroy))
      .subscribe((resp) => {
        if (resp && resp.status === 504) {
          this.modalService
            .open(dialog)
            .result
            .then((a) => {
              this.submit.next(true);
            }, function () {});
        }
      });
    return this;
  }

  setValidation(validationPostRequest, permissionStream) {
    validationPostRequest.response
      .pipe(takeUntil(this.component.mnOnDestroy))
      .subscribe(function () {
        validationPostRequest.clearError();
      });
    //skip initialization of the form
    ;(permissionStream || new BehaviorSubject(true)).pipe(
      switchMap((v) => v ? this.group.valueChanges : NEVER),
      throttleTime(500, undefined, {leading: true, trailing: true}),
      // Rx.operators.debounceTime(0),
      this.getPackPipe(),
      takeUntil(this.component.mnOnDestroy))
      .subscribe((v) => {
        validationPostRequest.post(v);
      });
    return this;
  }
}
