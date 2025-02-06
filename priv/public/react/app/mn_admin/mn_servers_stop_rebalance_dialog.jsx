import React from 'react';

const MnServersStopRebalanceDialog = ({ onClose, onDismiss }) => (
  <div className="dialog-med">
    <div className="panel-header">
      <h2>Confirm Rebalance Stop</h2>
    </div>
    <div className="panel-content">
      <p className="error">
        Warning: Stopping rebalance is unsafe at this moment since cluster may
        be in a partitioned state. Continue only if you're perfectly sure that
        this is not the case.
      </p>
    </div>
    <div className="panel-footer">
      <a onClick={onDismiss}>Cancel</a>
      <button type="submit" onClick={onClose}>
        Stop Rebalance
      </button>
    </div>
  </div>
);

export { MnServersStopRebalanceDialog };
