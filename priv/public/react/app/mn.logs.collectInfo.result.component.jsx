import React from 'react';
import { MnLifeCycleHooksToStream } from './mn.core.js';
import { filter, switchMap, skip } from 'rxjs/operators';
import { MnLogsCollectInfoService } from './mn.logs.collectInfo.service.js';
import { MnHelperReactService } from './mn.helper.react.service.js';
import { UIRouter } from 'mn.react.router';
import { MnSpinner } from './components/directives/mn_spinner.jsx';
import { MnLogsCollectInfoStopCollectionComponent } from './mn.logs.collectInfo.stop.collection.component.jsx';
import { ModalContext } from './uib/template/modal/window.and.backdrop.jsx';

class MnLogsCollectInfoResultComponent extends MnLifeCycleHooksToStream {
  static contextType = ModalContext;

  constructor(props) {
    super(props);

    this.state = {
      taskCollectInfo: null,
      disableStopCollection: false,
      nodesByStatus: null,
      nodesErrors: null,
      collectInfoLoading: true,
    };
  }

  componentDidMount() {
    super.componentDidMount();

    // Subscribe to task status
    this.taskCollectInfo = MnLogsCollectInfoService.stream.taskCollectInfo;
    MnHelperReactService.async(this, 'taskCollectInfo');

    // Subscribe to nodes status
    this.nodesByStatus =
      MnLogsCollectInfoService.stream.nodesByCollectInfoStatus;
    MnHelperReactService.async(this, 'nodesByStatus');

    // Subscribe to nodes errors
    this.nodesErrors = MnLogsCollectInfoService.stream.nodesErrors;
    MnHelperReactService.async(this, 'nodesErrors');

    // Subscribe to loading state
    this.collectInfoLoading = this.taskCollectInfo.pipe(skip(1));
    MnHelperReactService.async(this, 'collectInfoLoading');

    // Subscribe to stop collection state
    this.postCancelLogsCollection =
      MnLogsCollectInfoService.stream.postCancelLogsCollection;
    this.disableStopCollection = this.postCancelLogsCollection.success.pipe(
      switchMap(() => this.taskCollectInfo),
      filter((taskCollectInfo) => taskCollectInfo.status === 'running')
    );
    MnHelperReactService.async(this, 'disableStopCollection');
  }

  startNewCollection() {
    UIRouter.stateService.go('app.admin.logs.collectInfo.form');
  }

  stopCollection() {
    const { openModal } = this.context;
    openModal({
      component: MnLogsCollectInfoStopCollectionComponent,
    });
  }

  identifyNode(index, node) {
    return node.nodeName;
  }

  identifyNodeError(index, nodeError) {
    return nodeError.key;
  }

  render() {
    const {
      taskCollectInfo,
      disableStopCollection,
      nodesByStatus,
      nodesErrors,
      collectInfoLoading,
    } = this.state;

    return (
      <div>
        <div className="relative">
          <div
            className="row flex-right"
            style={{
              minHeight: 0,
              position: 'absolute',
              top: 0,
              right: 0,
              zIndex: 1,
            }}
          >
            <span>
              <button onClick={this.startNewCollection} className="outline">
                Start New Collection
              </button>
              {taskCollectInfo?.status === 'running' && (
                <button
                  onClick={this.stopCollection.bind(this)}
                  disabled={disableStopCollection}
                  className="outline"
                >
                  Stop Collection
                </button>
              )}
            </span>
          </div>
        </div>

        <MnSpinner mnSpinnerValue={collectInfoLoading}>
          <div
            className={`collection_status dynamic_${taskCollectInfo?.status}`}
          >
            <p>
              Collection {taskCollectInfo?.status}
              {taskCollectInfo?.status === 'running' && (
                <span>
                  <span className="loading"></span>
                </span>
              )}
            </p>
          </div>

          {nodesByStatus?.started && (
            <div className="margin-bottom-2">
              <p>In progress:</p>
              {nodesByStatus.started.map((node, i) => (
                <div key={this.identifyNode(i, node)}>{node.nodeName}</div>
              ))}
            </div>
          )}

          {nodesByStatus?.starting && (
            <div className="margin-bottom-2">
              <p>Pending:</p>
              {nodesByStatus.starting.map((node, i) => (
                <div key={this.identifyNode(i, node)}>{node.nodeName}</div>
              ))}
            </div>
          )}

          {nodesByStatus?.collected && (
            <div className="margin-bottom-2">
              <p>Logs were successfully collected to the following paths:</p>
              {nodesByStatus.collected.map((node, i) => (
                <div key={this.identifyNode(i, node)}>
                  <strong>{node.nodeName}</strong> &nbsp; {node.path}
                </div>
              ))}
            </div>
          )}

          {nodesByStatus?.startedUpload && (
            <div className="margin-bottom-2">
              <p>Logs are being uploaded from these paths:</p>
              {nodesByStatus.startedUpload.map((node, i) => (
                <div key={this.identifyNode(i, node)}>
                  <strong>{node.nodeName}</strong> {node.path}
                </div>
              ))}
            </div>
          )}

          {nodesByStatus?.startingUpload && (
            <div className="margin-bottom-2">
              <p className="success">
                Logs are pending upload from these paths:
              </p>
              {nodesByStatus.startingUpload.map((node, i) => (
                <div key={this.identifyNode(i, node)}>
                  <strong>{node.nodeName}</strong> {node.path}
                </div>
              ))}
            </div>
          )}

          {nodesByStatus?.uploaded && (
            <div className="margin-bottom-2">
              <p>Logs were successfully uploaded to the following URLs:</p>
              {nodesByStatus.uploaded.map((node, i) => (
                <div key={this.identifyNode(i, node)}>
                  <a href={node.url} target="_blank" rel="noopener noreferrer">
                    {node.url}
                  </a>
                </div>
              ))}
            </div>
          )}

          {nodesByStatus?.failedUpload && (
            <div className="margin-bottom-2">
              <p className="error">
                Warning: The following logs were successfully collected but
                failed to upload. Please manually upload from the following
                locations:
              </p>
              {nodesByStatus.failedUpload.map((node, i) => (
                <div key={this.identifyNode(i, node)}>
                  <strong>{node.nodeName}</strong> {node.path}
                </div>
              ))}
            </div>
          )}

          {nodesByStatus?.failed && (
            <div className="margin-bottom-2">
              <p className="error">
                Error: Unable to collect logs from the following nodes:
              </p>
              {nodesByStatus.failed.map((node, i) => (
                <div key={this.identifyNode(i, node)}>{node.nodeName}</div>
              ))}
            </div>
          )}

          {nodesByStatus?.cancelled && (
            <div className="margin-bottom-2">
              <p className="error">Cancelled nodes:</p>
              {nodesByStatus.cancelled.map((node, i) => (
                <div key={this.identifyNode(i, node)}>{node.nodeName}</div>
              ))}
            </div>
          )}

          {nodesErrors && (
            <div className="margin-top-1">
              <p className="error">Node errors:</p>
              {Object.entries(nodesErrors).map(([key, value], i) => (
                <div key={this.identifyNodeError(i, { key })}>
                  <strong>{key}</strong>
                  {value.map((error, j) => (
                    <p key={j} className="pre-line">
                      {error.error}
                    </p>
                  ))}
                </div>
              ))}
            </div>
          )}
        </MnSpinner>
      </div>
    );
  }
}

export { MnLogsCollectInfoResultComponent };
