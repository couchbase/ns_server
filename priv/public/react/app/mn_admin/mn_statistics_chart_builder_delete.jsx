import React from 'react';

const MnStatisticsChartBuilderDelete = ({ onClose, onDismiss, chartName }) => (
  <div className="dialog-small">
    <div className="panel-header">
      <h2>Delete Chart</h2>
    </div>
    <div className="panel-content">
      <div className="row flex-left">
        <span className="icon fa-warning fa-2x red-3"></span>
        <p>
          Are you sure you want to delete the chart {chartName}? This action
          cannot be undone.
        </p>
      </div>
    </div>
    <div className="panel-footer">
      <a onClick={onDismiss}>Cancel</a>
      <button type="submit" onClick={onClose}>
        Delete Chart
      </button>
    </div>
  </div>
);

export { MnStatisticsChartBuilderDelete };
