var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnSettings = (function (Rx) {
  "use strict";

  MnSettingsService.annotations = [
    new ng.core.Injectable()
  ];

  MnSettingsService.parameters = [
    ng.common.http.HttpClient
  ];

  MnSettingsService.prototype.postTestEmail = postTestEmail;
  MnSettingsService.prototype.postAlerts = postAlerts;
  MnSettingsService.prototype.getAlerts = getAlerts;

  return MnSettingsService;

  function MnSettingsService(http) {

    this.http = http;
    this.stream = {};

    this.stream.getAlerts =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getAlerts.bind(this)),
        Rx.operators.multicast(mn.helper.createReplaySubject),
        Rx.operators.refCount()
      );

    this.stream.postTestEmail =
      new mn.helper.MnPostHttp(this.postTestEmail.bind(this))
      .addSuccess()
      .addError();

    this.stream.postAlerts =
      new mn.helper.MnPostHttp(this.postAlerts.bind(this))
      .addSuccess()
      .addError();

    this.stream.postAlertsValidation =
      new mn.helper.MnPostHttp(this.postAlerts.bind(this))
      .addSuccess()
      .addError();
  }

  function postAlerts(data) {
    console.log(data)
    return this.http.post("/settings/alerts", data[0], {
      params: new ng.common.http.HttpParams().set("just_validate", data[1] ? 1 : 0)
    });
  }

  function postTestEmail(data) {
    return this.http.post("/settings/alerts/testEmail", data);
  }

  function getAlerts() {
    return this.http.get("/settings/alerts");
  }

})(window.rxjs);
