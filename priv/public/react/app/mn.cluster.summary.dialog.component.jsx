import React from 'react';
import { map } from 'rxjs/operators';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { MnLogsCollectInfoService } from './mn.logs.collectInfo.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import MnAlertsService from './components/mn_alerts.js';
import { MnSpinner } from './components/directives/mn_spinner.jsx';
import { CopyToClipboard } from 'react-copy-to-clipboard';

class MnClusterSummaryDialogComponent extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);

    this.state = {
      clusterInfo: null,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    // Subscribe to cluster info
    this.clusterInfo = MnLogsCollectInfoService.stream.clusterInfo.pipe(
      map((v) => JSON.stringify(v, null, 2))
    );
    MnHelperReactService.async(this, 'clusterInfo');
  }

  render() {
    const { onDismiss } = this.props;
    const { clusterInfo } = this.state;

    return (
      <div className="dialog-med height-85vh">
        <div className="panel-header">
          <h2>Cluster Summary Info</h2>
          <a
            className="ui-dialog-titlebar-close modal-close"
            onClick={onDismiss}
          >
            X
          </a>
        </div>

        {/* TODO <MnSpinner mnSpinnerValue={!clusterInfo}> */}
        <div
          style={{
            height: 'calc(100% - 112px)',
            overflow: 'auto',
            margin: '.5rem 0 0 0',
          }}
          className="show-scrollbar"
        >
          <div className="panel-content">
            <pre id="cluster_info" className="text-small">
              {clusterInfo}
            </pre>
          </div>
        </div>
        {/* </MnSpinner> */}

        <div className="panel-footer spaced scroll-shadow margin-top-quarter">
          <CopyToClipboard
            text={clusterInfo || ''}
            onCopy={(text, result) => {
              if (result) {
                MnAlertsService.formatAndSetAlerts(
                  'Text copied successfully!',
                  'success',
                  2500
                );
              } else {
                MnAlertsService.formatAndSetAlerts(
                  'Unable to copy text!',
                  'error',
                  2500
                );
              }
              onDismiss();
            }}
          >
            <button className="outline" disabled={!clusterInfo}>
              Copy to Clipboard
            </button>
          </CopyToClipboard>
          <a onClick={onDismiss}>Close</a>
        </div>
      </div>
    );
  }
}

export { MnClusterSummaryDialogComponent };
