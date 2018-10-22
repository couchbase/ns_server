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
  Form.prototype.message = message;
  Form.prototype.disableFields = disableFields;
  Form.prototype.setValidation = setValidation;
  Form.prototype.setUnpackPipe = setUnpackPipe;
  Form.prototype.setPackPipe = setPackPipe;

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
  }

  function setFormGroup(formDescription) {
    this.group = this.builder.group(formDescription);
    return this;
  }

  function setSource(source) {
    this.sourcePipe = source.pipe(Rx.operators.first(),
                                  this.unpackPipe || Rx.operators.tap());

    this.changes = Rx.merge(this.group.valueChanges, this.sourcePipe);

    this.sourcePipe.subscribe(function (v) {
      this.group.patchValue(v, {emitEvent: false});
    }.bind(this));
    return this;
  }

  function message(message) {
    this.postRequest.success
      .pipe(Rx.operators.takeUntil(this.component.mnOnDestroy))
      .subscribe(this.mnAlertsService.success(message));
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
      .pipe(this.packPipe || Rx.operators.tap(),
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
            Rx.operators.debounceTime(0),
            this.packPipe || Rx.operators.tap(),
            Rx.operators.takeUntil(this.component.mnOnDestroy))
      .subscribe(function (v) {
        validationPostRequest.post(v);
      }.bind(this));
    return this;
  }

})(window.rxjs);
