import { BehaviorSubject } from 'rxjs';
import { MnAlertsPopupMessage } from './mn_alerts_popup_message.jsx';

const alerts = new BehaviorSubject([]);
const alertsHistory = [];
const clientAlerts = new BehaviorSubject({
  hideCompatibility: false,
});

const mnAlertsService = {
  setAlert,
  formatAndSetAlerts,
  showAlertInPopup,
  alerts,
  removeItem,
  isNewAlert,
  clientAlerts,
};

export default mnAlertsService;

function showAlertInPopup(message, title, openModal) {
  const scope = {
    message: message,
    title: title,
  };
  // Using a promise wrapper
  return openModal({
    component: MnAlertsPopupMessage,
    props: scope,
  });
}

function isNewAlert(item) {
  const findedItem = alertsHistory.find((alert) => alert === item);
  return alertsHistory.indexOf(findedItem) === -1;
}

function startTimer(item, timeout) {
  return setTimeout(
    () => {
      removeItem(item);
    },
    parseInt(timeout, 10)
  );
}

function removeItem(item) {
  const currentAlerts = alerts.getValue();
  const index = currentAlerts.indexOf(item);
  if (item.timeout) {
    clearTimeout(item.timeout);
  }
  const newAlerts = [
    ...currentAlerts.slice(0, index),
    ...currentAlerts.slice(index + 1),
  ];
  alerts.next(newAlerts);
}

function setAlert(type, message, timeout, id) {
  const item = {
    type: type || 'error',
    msg: message,
    id: id,
  };

  const currentAlerts = alerts.getValue();
  const findedItem = currentAlerts.find(
    (alert) => alert.type === type && alert.msg === message
  );

  if (findedItem) {
    removeItem(findedItem);
  }

  const newAlerts = [...currentAlerts, item];
  alerts.next(newAlerts);
  alertsHistory.push(item);

  if (timeout) {
    item.timeout = startTimer(item, timeout);
  }
}

function formatAndSetAlerts(incomingAlerts, type, timeout = 60000 * 5) {
  if (Array.isArray(incomingAlerts) && typeof incomingAlerts[0] === 'string') {
    incomingAlerts.forEach((msg) => {
      setAlert(type, msg, timeout);
    });
  } else if (typeof incomingAlerts === 'object') {
    Object.values(incomingAlerts).forEach((msg) => {
      setAlert(type, msg, timeout);
    });
  } else if (typeof incomingAlerts === 'string') {
    setAlert(type, incomingAlerts, timeout);
  }
}
