import React from 'react';

const MnGsiDropConfirmDialog = ({ partitioned, onClose, onDismiss }) => (
  <div className="dialog-small">
    <div className="panel-header">
      <h2>Drop Index</h2>
    </div>
    <div className="panel-content">
      <div className="row flex-left">
        <span className="icon fa-warning fa-2x red-3"></span>
        <p>
          Are you sure want to drop this index?
          {partitioned && (
            <span>
              <br />
              All partitions of this index will be dropped.
            </span>
          )}
        </p>
      </div>
    </div>
    <div className="panel-footer">
      <a onClick={onDismiss}>Cancel</a>
      <button type="submit" onClick={onClose}>
        Drop Index
      </button>
    </div>
  </div>
);

export { MnGsiDropConfirmDialog };
