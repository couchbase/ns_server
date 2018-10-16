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
  Form.prototype.submittable = submittable;
  Form.prototype.clearErrors = clearErrors;
  Form.prototype.message = message;
  Form.prototype.disableFields = disableFields;

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
    source
      .pipe(Rx.operators.first())
      .subscribe(function (v) {
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

  function submittable(postRequest, getValueStream) {
    this.postRequest = postRequest;
    this.submit = new Rx.Subject();

    this.submit
      .pipe(getValueStream,
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

})(window.rxjs);
