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
  MnSettingsService.prototype.getAutoCompaction = getAutoCompaction;
  MnSettingsService.prototype.postAutoCompaction = postAutoCompaction;

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

    this.stream.getAutoCompaction =
      (new Rx.BehaviorSubject()).pipe(
        Rx.operators.switchMap(this.getAutoCompaction.bind(this)),
        Rx.operators.map(function (v) {
          var ac = v.autoCompactionSettings;
          ac.indexCircularCompaction.daysOfWeek =
            ac.indexCircularCompaction.daysOfWeek.split(",").reduce(function (acc, day) {
              acc[day] = true;
              return acc;
            }, {});
          ac.purgeInterval = v.purgeInterval;
          return ac;
        }),
        Rx.operators.multicast(mn.helper.createReplaySubject),
        Rx.operators.refCount()
      );

    this.stream.getAutoCompactionFirst =
      this.stream.getAutoCompaction.pipe(Rx.operators.first());

    this.stream.postAutoCompaction =
      new mn.helper.MnPostHttp(this.postAutoCompaction.bind(this))
      .addSuccess()
      .addError();

    this.stream.postAutoCompactionValidation =
      new mn.helper.MnPostHttp(this.postAutoCompaction.bind(this))
      .addSuccess()
      .addError();

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

  function getAutoCompaction(data) {
    return this.http.get("/settings/autoCompaction");
  }

  function postAutoCompaction(data) {
    return this.http.post("/controller/setAutoCompaction", data[0], {
      params: new ng.common.http.HttpParams().set("just_validate", data[1] ? 1 : 0)
    });
  }

})(window.rxjs);
