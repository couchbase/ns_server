import React from 'react';

const MnStatisticsScenarioDelete = ({ onClose, onDismiss }) => (
  <div className="dialog-small">
    <h2 className="panel-header">Delete Custom Dashboard</h2>
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <div className="panel-content">
        <div className="row flex-left">
          <span className="icon fa-warning fa-2x red-3"></span>
          <p>Delete this dashboard?</p>
        </div>
      </div>
      <div className="panel-footer">
        <a onClick={onDismiss}>Cancel</a>
        <button type="submit" autoFocus>
          Delete Dashboard
        </button>
      </div>
    </form>
  </div>
);

export { MnStatisticsScenarioDelete };
