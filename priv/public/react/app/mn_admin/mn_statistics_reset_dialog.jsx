import React from 'react';

const MnStatisticsResetDialog = ({ onClose, onDismiss }) => (
  <div className="dialog-small">
    <div className="panel-header">
      <h2>Reset Dashboard</h2>
    </div>
    <div className="panel-content">
      <div className="row flex-left">
        <span className="icon fa-warning fa-2x red-3"></span>
        <p>
          This will permanently delete all your custom dashboard configurations
          and reset your dashboard to its initial state.
        </p>
      </div>
    </div>
    <div className="panel-footer">
      <a onClick={onDismiss}>Cancel</a>
      <button
        type="submit"
        onClick={onClose}>Reset Dashboard</button>
    </div>
  </div>
);

export { MnStatisticsResetDialog }; 