import { MnLifeCycleHooksToStream } from '../mn.core.js';
import _ from 'lodash';
import dayjs from 'dayjs';
import { ModalContext } from '../uib/template/modal/window.and.backdrop';
import { MnGsiDropConfirmDialog } from './mn_gsi_drop_confirm_dialog';
import mnGsiService from './mn_gsi_service';
import mnAlertsService from '../components/mn_alerts';
import mnPromiseHelper from '../components/mn_promise_helper';
import mnPermissions from '../components/mn_permissions';
import { mnFormatStorageMode } from '../components/mn_filters';
import { UISref } from '@uirouter/react';


class MnGsiItemController extends MnLifeCycleHooksToStream {
  componentDidMount() {
    var row = this.props.row;

    //check permissions
    let interestingPermissions = row.collection ?
        mnPermissions.getPerCollectionPermissions(row.bucket, row.scope, row.collection) :
        mnPermissions.getPerScopePermissions(row.bucket, row.scope);
    interestingPermissions.forEach(mnPermissions.set);
    mnPermissions.throttledCheck();
  }
  render() {
    return <>{this.props.children}</>
  }
}

class MnGsiItemDetails extends MnLifeCycleHooksToStream {
  static contextType = ModalContext;

  constructor(props) {
    super(props);
  }
  componentWillMount() {
    var vm = this;
    vm.dropIndex = dropIndex;
    vm.getFormattedScanTime = getFormattedScanTime;
    var row = this.props.row;
    const $uibModal = this.context;

    vm.keyspace = row.bucket + ":" + row.scope + (row.collection ? (":" + row.collection) : "");

    function getFormattedScanTime(row) {
      if (row && row.lastScanTime != 'NA')
        return dayjs(row.lastScanTime).format('hh:mm:ss A, D MMM, YYYY');
      else
        return 'NA';
    }

    function dropIndex(row, dropReplicaOnly) {
      $uibModal.openModal({
        component: MnGsiDropConfirmDialog,
        props: {
          partitioned: row.partitioned
        }
      }).then(function () {
        row.awaitingRemoval = true;
        vm.props.updateState();

        mnPromiseHelper(vm, mnGsiService.postDropIndex(row, dropReplicaOnly))
          .showGlobalSpinner()
          .catchErrors(function (resp) {
            if (!resp) {
              return;
            } else if (_.isString(resp)) {
              mnAlertsService.formatAndSetAlerts(resp.data, "error", 4000);
            } else if (resp.errors && resp.errors.length) {
              mnAlertsService.formatAndSetAlerts(_.map(resp.errors, "msg"), "error", 4000);
            }
            row.awaitingRemoval = false;
            vm.props.updateState();

          })
          .showGlobalSuccess("Index dropped successfully!")
          .catchGlobalErrors("Error dropping index.");
        }, () => {});
    }
  }
  render() {
    const vm = this;
    const { row, pools, rbac, nodeName } = this.props;
    return (
      <span className={this.props.className}>
        <div className="indent-1 cursor-auto">
          <div className="row items-bottom margin-bottom-1">
            <div className="margin-right-4">
              <div onClick={(e) => e.stopPropagation()} className="break-word margin-bottom-half">
                <strong>Definition</strong> {row.definition}
              </div>
              <div>
                <strong>Storage Mode</strong> {mnFormatStorageMode(row.storageMode, pools.isEnterprise)} &nbsp;&nbsp;
                {!row.partitioned && row.hosts.length > 1 && (
                  <span className="margin-bottom-0">
                    <strong>Nodes</strong> {row.hosts.join(', ')}
                  </span>
                )}
                {row.partitioned && (
                  <span className="margin-bottom-0">
                    <strong>Nodes</strong>
                    {Object.entries(row.partitionMap).map(([node, partitions], index, array) => (
                      <span key={node}>
                        {node} ({partitions.length} partition{partitions.length !== 1 ? 's' : ''})
                        {index !== array.length - 1 ? ',' : ''}
                      </span>
                    ))}
                  </span>
                )}
              </div>
              {row.lastScanTime && row.lastScanTime !== 'NA' && (
                <div>
                  <strong>Last Scanned</strong> {vm.getFormattedScanTime(row)}
                </div>
              )}
            </div>
            <div className="nowrap margin-right-1">
              <UISref to="app.admin.query.workbench" params={{ query: row.definition }}>
                <button className="outline tight">Open in Workbench</button>
              </UISref>
              {rbac.cluster.collection[vm.keyspace]?.n1ql.select.execute && (
                <>
                  <button className="outline tight" onClick={() => vm.dropIndex(row)}>
                    Drop {row.numReplica > 0 && 'All Replicas'}
                  </button>
                  {row.numReplica > 0 && (
                    <button className="outline tight" onClick={() => vm.dropIndex(row, true)}>
                      Drop This Replica
                    </button>
                  )}
                </>
              )}
            </div>
          </div>
          {/* <mn-detail-stats
            node-name={nodeName || 'all'}
            bucket={row.bucket}
            mn-title="Index Stats"
            item-id={row.index}
            service="index"
            prefix="index"
          /> */}
        </div>
      </span>
    );
  }
}

export { MnGsiItemDetails, MnGsiItemController };