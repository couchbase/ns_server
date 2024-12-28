import React from 'react';
import { Subject } from 'rxjs';
import mnHelper from '../components/mn_helper';
import { MnHelperService  } from '../mn.helper.service';
import { MnLifeCycleHooksToStream } from '../mn.core.js';

import { mnFormatQuantity } from '../components/mn_filters.js';
import { MnSortableTable, MnSortableTitle }  from '../components/directives/mn_sortable_table.jsx';
import { MnGsiItemDetails, MnGsiItemController } from './mn_gsi_item_details.jsx';
import { angularJSLikeFilter } from '../components/mn_filters.js';
import { NgbPagination } from '../uib/pagination';
import { MnSelect } from '../components/directives/mn_select/mn_select.jsx';
import { Tooltip, OverlayTrigger } from 'react-bootstrap';

class MnGsiTable extends MnLifeCycleHooksToStream {
  constructor(props) {
    super(props);
    this.sortableTableProperties = React.createRef();
    this.state = {
      paginatorPage: null,
      paginatorValues: null,
      listFiltered: null,

      orderBy: null,
      invert: false,

      updateState: 0
    }
  }

  updateState = () => {
    this.setState({updateState: this.state.updateState + 1});
  }

  filterAndSortList() {
    const vm = this;
    const newlist = angularJSLikeFilter(
      this.sortableTableProperties.current.orderBy(vm.props.list),
      vm.props.filterField
    );
    vm.setState({listFiltered: newlist});
    if (newlist) {
      vm.paginationStream.next(newlist);
    }
  }

  componentDidUpdate(prevProps, prevState) {
    var vm = this;
    if (
      prevProps.list !== vm.props.list ||
      prevProps.filterField !== vm.props.filterField ||
      prevState.orderBy !== vm.state.orderBy ||
      prevState.invert !== vm.state.invert
    ) {
      vm.filterAndSortList();
    }
  }

  componentDidMount() {
    var vm = this;
    vm.generateIndexId = generateIndexId;
    vm.getStatusClass = getStatusClass;
    vm.getStatusDescription = getStatusDescription;
    vm.pageChanged = pageChanged;
    vm.sizeChanged = sizeChanged;
    vm.getRowKeyspace = getRowKeyspace;
    vm.isFinite = Number.isFinite;

    mnHelper.initializeDetailsHashObserver(vm, 'openedIndex', 'app.admin.gsi');

    let mnOnDestroy = new Subject();
    vm.paginationStream = new Subject();
    let paginator = MnHelperService.createPagenator(
      {mnOnDestroy},
      vm.paginationStream,
      vm.props.nodeName ? "perNodePage" : "perIndexPage",
      vm.props.nodeName || null,
      vm,
      15
    );

    // TODO: Add poller
    // vm.mnGsiStatsPoller = mnStatisticsNewService.createStatsPoller($scope);

    vm.paginator = paginator;

    vm.$on("$destroy", function () {
      mnOnDestroy.next();
      mnOnDestroy.complete();
    });

    vm.filterAndSortList();

    function sizeChanged({selectedOption}) {
      paginator.group.patchValue({size: selectedOption});
    }

    function pageChanged(value) {
      paginator.group.patchValue({page: value});
    }

    function getRowKeyspace(row) {
      return row.bucket + (row.scope ?
                           ("."+row.scope) + (row.collection ?
                                              "."+row.collection : "") : "")
    }

    function generateIndexId(row) {
      return (row.id.toString() + (row.instId || "")) +
        (row.hosts ? row.hosts.join() : "") +
        (vm.props.nodeName || "");
    }

    function getStatusClass(row) {
      row = row || {};
      if (row.stale) { //MB-36247
        return 'dynamic_warmup';
      }
      switch (row.status) {
      case 'Ready': return 'dynamic_healthy';
      case 'Not Available': return 'dynamic_unhealthy';
      case 'Error': return 'dynamic_unhealthy';
      case 'Paused': return 'dynamic_unhealthy';
      case 'Replicating':
      case 'Created':
      case 'Building':
      case 'Warmup':
      case 'Created (Upgrading)':
      case 'Created (Downgrading)':
      case 'Building (Upgrading)':
      case 'Building (Downgrading)': return 'dynamic_warmup';
      default: return 'dynamic_warmup';
      }
    }
    function getStatusDescription(row) {
      row = row || {};
      switch (row.status) {
      case 'Created': return 'Index definition has been saved. Use Build Index to build the index. It is NOT serving scan requests yet.';
      case 'Building': return 'Index is currently building. It is NOT serving scan requests yet.';
      case 'Ready': return 'Index is ready to serve scan requests.';
      case 'Replicating': return 'Index is being replicated as part of a Rebalance or Alter Index operation. It is NOT serving scan requests until replication is complete.';
      case 'Paused': return 'Index is not ingesting new mutations as allocated memory has been completely used.';
      case 'Warmup': return 'Index is being loaded from persisted on-disk snapshot after indexer process restart. It is NOT serving scan requests yet.';
      case 'Error': return 'Index is in an error state and cannot be used in scan operations.';
      case 'Created (Upgrading)': return 'Index definition has been upgraded from Legacy storage engine to Standard GSI. It is NOT serving scan requests yet.';
      case 'Created (Downgrading)': return 'Index definition has been downgraded from Standard GSI to Legacy storage engine. It is NOT serving scan requests yet.'  ;
      case 'Building (Upgrading)': return 'Index is building after upgrade from Legacy storage engine to Standard GSI. It is NOT serving scan requests yet.';
      case 'Building (Downgrading)': return 'Index is building after downgrade from Standard GSI to Legacy storage engine. It is NOT serving scan requests yet.';
      case 'Not Available': return 'Index not available.';
      }
    }

  }
  render() {
    const vm = this;
    const { pools, rbac, list } = vm.props;
    const { paginatorPage, paginatorValues, listFiltered } = vm.state;

    return (
      <MnSortableTable className="cbui-table" ref={vm.sortableTableProperties} setState={vm.setState.bind(vm)} state={vm.state}>
        <div className="cbui-table-header">
          <span className="cbui-table-cell flex-grow-1-5">
            <MnSortableTitle mnSortableTitle="index" sortByDefault="true" className="sorter">
              index name
            </MnSortableTitle>
          </span>
          <span className="cbui-table-cell flex-grow-half resp-hide-xsml">
            requests/sec
          </span>
          <span className="cbui-table-cell flex-grow-half resp-hide-sml">
            resident ratio
          </span>
          <span className="cbui-table-cell flex-grow-half">
            items
          </span>
          <span className="cbui-table-cell flex-grow-half resp-hide-xsml">
            data size
          </span>
          <span className="cbui-table-cell">
            <MnSortableTitle mnSortableTitle="keyspace" className="sorter">
              keyspace
            </MnSortableTitle>
          </span>
          <span className="cbui-table-cell">
            <MnSortableTitle mnSortableTitle="status" className="sorter">
              status
            </MnSortableTitle>
          </span>
        </div>
        {paginatorPage?.map(row => (
          <section
            key={vm.generateIndexId(row)}
            className={`${vm.isDetailsOpened(vm.generateIndexId(row)) ? vm.getStatusClass(row) : ''} ${(row.awaitingRemoval ? 'disabled-tag' : '')}`}
            onClick={() => vm.toggleDetails(vm.generateIndexId(row))}>
            <MnGsiItemController row={row}>
              <div className={`cbui-tablerow has-hover ${!vm.isDetailsOpened(vm.generateIndexId(row)) ? vm.getStatusClass(row) : ''}`}>
                <span className="cbui-table-cell flex-grow-1-5" title={row.index}>
                  {row.indexName || row.index}
                  <span className="flex-inline flex-wrap">
                    {row.partitioned && <span className="label lt-blue">partitioned</span>}
                    {row.stale && <span className="label warning">stale</span>}
                    {row.index.indexOf('(replica') > -1 && (
                      <OverlayTrigger
                        placement="auto"
                        overlay={<Tooltip id="replicas-tooltip">Index replicas are always active and automatically load-balance scan requests.</Tooltip>}
                        trigger={['hover']}>
                          <span className="label lt-blue">
                            replica {row.index.split("(replica ")[1].slice(0, -1)}
                          </span>
                      </OverlayTrigger>
                    )}
                  </span>
                </span>
                <span className="cbui-table-cell flex-grow-half resp-hide-xsml">
                  {vm.isFinite(row.num_requests) ? mnFormatQuantity(row.num_requests, 1000) : "-"}
                </span>
                <span className="cbui-table-cell flex-grow-half resp-hide-sml">
                  {vm.isFinite(row.index_resident_percent) ? `${row.index_resident_percent}%` : "-"}
                </span>
                <span className="cbui-table-cell flex-grow-half">
                  {vm.isFinite(row.items_count) ? mnFormatQuantity(row.items_count, 1000) : "-"}
                </span>
                <span className="cbui-table-cell flex-grow-half resp-hide-xsml">
                  {vm.isFinite(row.data_size) ? mnFormatQuantity(row.data_size) : "-"}
                </span>
                <span className="cbui-table-cell" title={vm.getRowKeyspace(row)}>
                  {vm.getRowKeyspace(row)}
                </span>
                <span className="cbui-table-cell flex-wrap text-smaller">
                  {row.status === 'Building' ? (
                    <OverlayTrigger
                      placement="left"
                      overlay={<Tooltip id="building-tooltip">{vm.getStatusDescription(row)}</Tooltip>}
                      trigger={['hover']} >
                      <div onClick={e => e.stopPropagation()}>
                        building {row.progress}%
                      </div>
                    </OverlayTrigger>
                  ) : (
                    <OverlayTrigger
                      placement="left"
                      overlay={<Tooltip id="status-tooltip">{vm.getStatusDescription(row)}</Tooltip>}
                      trigger={['hover']}>
                      <div onClick={e => e.stopPropagation()} className="nocaps">
                        {row.status}
                      </div>
                    </OverlayTrigger>
                  )}
                  {vm.isFinite(row['num_docs_pending+queued']) && row['num_docs_pending+queued'] !== 0 && (
                    <div className="label warning">
                      {mnFormatQuantity(row['num_docs_pending+queued'], 1000)} mutations remaining
                    </div>
                  )}
                </span>
              </div>
            </MnGsiItemController>
            {vm.isDetailsOpened(vm.generateIndexId(row)) && (<MnGsiItemDetails
              updateState={vm.updateState}
              className="cbui-tablerow-expanded"
              row={row}
              nodeName={vm.props.nodeName}
              rbac={rbac}
              pools={pools}
            />)}
          </section>
        ))}
        {paginatorPage?.length === 0 && (
          <div className="zero-content margin-top-1-5">
            No indexes found for this bucket.scope combination. Try another bucket.scope.
          </div>
        )}
        <div className="row">
          <MnSelect
            className="mn-select-small fix-width-3-quarters margin-top-half"
            value={paginatorValues?.size}
            values={[5, 15, 20, 40, 80]}
            onSelect={vm.sizeChanged}
            openOnTop={true}
          />
          {list.length && 
            <NgbPagination
              page={paginatorValues?.page}
              maxSize={5}
              pageSize={paginatorValues?.size}
              collectionSize={listFiltered?.length}
              onPageChange={vm.pageChanged}
            />}
        </div>
      </MnSortableTable>
    );
  };
}

export {MnGsiTable};
