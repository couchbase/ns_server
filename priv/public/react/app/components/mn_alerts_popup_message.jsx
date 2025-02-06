const MnAlertsPopupMessage = ({ title, message, onClose }) => {
  const isArray = Array.isArray(message);
  const isObject = typeof message === 'object' && !isArray;
  const isString = typeof message === 'string';

  return (
    <div className="dialog-med">
      <h2 className="panel-header">{title}</h2>
      <div className="panel-content">
        {isArray && (
          <div className="error">
            {message.map((text, index) => (
              <div key={index}>{text}</div>
            ))}
          </div>
        )}
        {isObject && (
          <div className="error">
            {Object.keys(message).map((key, index) => (
              <div key={index}>{message[key]}</div>
            ))}
          </div>
        )}
        {isString && <div className="error">{message}</div>}
      </div>
      <div className="panel-footer">
        <button onClick={onClose}>OK</button>
      </div>
    </div>
  );
};

export { MnAlertsPopupMessage };
