var mn = mn || {};
mn.services = mn.services || {};
mn.services.MnAlerts = (function (Rx) {
  "use strict";

  MnAlertsService.annotations = [
    new ng.core.Injectable()
  ];

  MnAlertsService.parameters = [];

  MnAlertsService.prototype.setAlert = setAlert;
  MnAlertsService.prototype.removeItem = removeItem;
  MnAlertsService.prototype.startTimer = startTimer
  MnAlertsService.prototype.success = success;

  return MnAlertsService;

  function MnAlertsService() {
    this.alerts = [];
    this.stream = {};
    this.stream.alert = new Rx.Subject();

    this.stream.alerts = this.stream.alert.pipe(
      Rx.operators.tap(function () {
        window.scrollTo(0, 0);
      }),
      Rx.operators.map(this.setAlert.bind(this))
    );
  }

  function success(message) {
    return function () {
      this.stream.alert.next({
        message: message,
        type: "success",
        timeout: 4000
      })
    }.bind(this)
  }

  function startTimer(item, timeout) {
    return setTimeout(function () {
      this.removeItem(item);
    }.bind(this), parseInt(timeout, 10));
  }

  function removeItem(item) {
    var index = _.indexOf(this.alerts, item);
    item.timeout && clearTimeout(item.timeout);
    this.alerts.splice(index, 1);
  }

  // type, message, timeout, id
  function setAlert(alert) {
    //in case we get alert with the same message
    //but different id find and remove it
    var findedItem = _.find(this.alerts, {
      type: alert.type,
      message: alert.message
    });

    findedItem && this.removeItem(findedItem);
    alert.timeout && (alert.timeout = this.startTimer(alert, alert.timeout));

    this.alerts.push(alert);
    // alertsHistory.push(item);
    return this.alerts;
  }

})(window.rxjs);
