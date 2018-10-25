var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnForm = (function (Rx) {

  MnForm.annotations = [
    new ng.core.Injectable()
  ];

  MnForm.parameters = [
    ng.forms.FormBuilder,
    mn.services.MnAlerts
  ];

  MnForm.prototype.create = create;

  Form.prototype.setFormGroup = setFormGroup;
  Form.prototype.setSource = setSource;
  Form.prototype.setPostRequest = setPostRequest;
  Form.prototype.clearErrors = clearErrors;
  Form.prototype.successMessage = successMessage;
  Form.prototype.errorMessage = errorMessage;
  Form.prototype.disableFields = disableFields;
  Form.prototype.setValidation = setValidation;
  Form.prototype.setUnpackPipe = setUnpackPipe;
  Form.prototype.setPackPipe = setPackPipe;
  Form.prototype.getFormValue = getFormValue;
  Form.prototype.success = success;
  Form.prototype.error = error;

  return MnForm;

  function MnForm(formBuilder, mnAlertsService) {
    this.formBuilder = formBuilder;
    this.mnAlertsService = mnAlertsService;
  }

  function create(component) {
    return new Form(this.formBuilder, component, this.mnAlertsService);
  }

  function Form(builder, component, mnAlertsService) {
    this.builder = builder;
    this.component = component;
    this.mnAlertsService = mnAlertsService;
    this.packPipe = Rx.pipe(Rx.operators.map(this.getFormValue.bind(this)));
  }

  function getFormValue() {
    return this.group.value;
  }

  function setFormGroup(formDescription) {
    this.group = this.builder.group(formDescription);
    return this;
  }

  function setSource(source) {
    this.sourcePipe = source.pipe(this.unpackPipe || Rx.operators.tap(),
                                  Rx.operators.first());

    this.changes = Rx.merge(this.group.valueChanges, this.sourcePipe);

    this.sourcePipe.subscribe(function (v) {
      this.group.patchValue(v, {emitEvent: false});
    }.bind(this));
    return this;
  }

  function success(fn) {
    this.postRequest.success
      .pipe(Rx.operators.takeUntil(this.component.mnOnDestroy))
      .subscribe(fn);
    return this;
  }

  function error(fn) {
    this.postRequest.error
      .pipe(Rx.operators.takeUntil(this.component.mnOnDestroy))
      .subscribe(fn);
    return this;
  }

  function successMessage(message) {
    this.success(this.mnAlertsService.success(message));
    return this;
  }

  function errorMessage(message) {
    this.error(this.mnAlertsService.error(message));
    return this;
  }

  function disableFields(path) {
    return function (value) {
      this.group.get(path)[value ? "disable" : "enable"]({emitEvent: false});
    }.bind(this);
  }

  function setPostRequest(postRequest) {
    this.postRequest = postRequest;
    this.submit = new Rx.Subject();

    this.submit
      .pipe(this.group ? this.packPipe : Rx.operators.tap(),
            Rx.operators.takeUntil(this.component.mnOnDestroy))
      .subscribe(function (v) {
        this.postRequest.post(v);
      }.bind(this));
    return this;
  }

  function clearErrors() {
    this.submit
      .pipe(Rx.operators.takeUntil(this.component.mnOnDestroy))
      .subscribe(function () {
        this.postRequest.clearError();
      }.bind(this));
    return this;
  }

  function setUnpackPipe(unpackPipe) {
    this.unpackPipe = unpackPipe;
    return this;
  }

  function setPackPipe(packPipe) {
    this.packPipe = packPipe;
    return this;
  }

  function setValidation(validationPostRequest, permissionStream) {
    permissionStream
      .pipe(Rx.operators.switchMap(function (v) {
        return v ? this.group.valueChanges : Rx.NEVER;
      }.bind(this)),
            // Rx.operators.throttleTime(500, undefined, {leading: true, trailing: true})
            Rx.operators.debounceTime(0),
            this.packPipe,
            Rx.operators.takeUntil(this.component.mnOnDestroy))
      .subscribe(function (v) {
        validationPostRequest.post(v);
      }.bind(this));
    return this;
  }

})(window.rxjs);
