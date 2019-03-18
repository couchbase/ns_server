(function () {
  "use strict";

  angular
    .module('mnStatisticsDescriptionService', [])
    .factory('mnStatisticsDescriptionService', mnStatisticsDescriptionFactory);

  function mnStatisticsDescriptionFactory() {
    return {
      "kvGroups": {
        "Ops":
        ["cas_hits","couch_views_ops","ep_num_ops_del_meta","ep_num_ops_get_meta","ep_num_ops_set_meta","ep_ops_create","ep_ops_update","ops","vb_active_ops_create","vb_pending_ops_create","vb_replica_ops_create","xdc_ops"],
        "Memory":
        ["ep_meta_data_memory","ep_tmp_oom_errors","mem_used","vb_active_itm_memory","vb_active_meta_data_memory","vb_pending_itm_memory","vb_pending_meta_data_memory","vb_replica_itm_memory","vb_replica_meta_data_memory"],
        "Disk":
        ["couch_total_disk_size","ep_cache_miss_rate","vb_avg_total_queue_age","avg_disk_update_time","avg_disk_commit_time","couch_docs_actual_disk_size","couch_views_actual_disk_size",
         "disk_write_queue","ep_bg_fetched","ep_data_read_failed","ep_data_write_failed","ep_diskqueue_drain","ep_diskqueue_fill","ep_diskqueue_items","ep_num_value_ejects","ep_ops_create",
         "ep_ops_update","vb_active_eject","vb_active_queue_drain","vb_active_queue_fill","vb_active_queue_size","vb_pending_eject"],
        "vBucket":
        ["vb_pending_resident_items_ratio","avg_active_timestamp_drift","avg_replica_timestamp_drift","ep_active_ahead_exceptions","ep_replica_ahead_exceptions","ep_vb_total",
         "vb_active_eject","vb_active_num","vb_active_ops_create","vb_pending_curr_items","vb_pending_eject","vb_pending_num","vb_pending_ops_create","vb_replica_curr_items","vb_replica_eject","vb_replica_num","vb_replica_ops_create"],
        "Disk Queues":
        ["ep_diskqueue_fill","vb_active_queue_fill","vb_pending_queue_fill","vb_replica_queue_fill"],
        "DCP Queues":
        ["ep_dcp_views+indexes_count","ep_dcp_views+indexes_producer_count","ep_dcp_views+indexes_total_bytes","ep_dcp_views+indexes_backoff","curr_connections","ep_dcp_cbas_backoff","ep_dcp_cbas_count","ep_dcp_cbas_producer_count","ep_dcp_cbas_total_bytes","ep_dcp_other_backoff","ep_dcp_other_count","ep_dcp_other_producer_count","ep_dcp_other_total_bytes","ep_dcp_replica_backoff","ep_dcp_replica_count","ep_dcp_replica_producer_count","ep_dcp_replica_total_bytes","ep_dcp_xdcr_backoff","ep_dcp_xdcr_count","ep_dcp_xdcr_producer_count","ep_dcp_xdcr_total_bytes"]
      },
      "stats": {
        "@kv-": {
          "couch_total_disk_size": {
            unit: "byte",
            title: "total disk size",
            desc: "The total size on disk of all data and view files for this bucket (measured from couch_total_disk_size)"
          },
          "couch_docs_fragmentation": {
            unit: "percent",
            title: "docs fragmentation %",
            desc: "How much fragmented data there is to be compacted compared to real data for the data files in this bucket (measured from couch_docs_fragmentation)"
          },
          "couch_views_fragmentation": {
            unit: "percent",
            title: "views fragmentation %",
            desc: "How much fragmented data there is to be compacted compared to real data for the view index files in this bucket (measured from couch_views_fragmentation)"
          },
          "hit_ratio": {
            unit: "percent",
            title: "hit ratio",
            desc: "Percentage of get requests served with data from this bucket (measured from get_hits * 100/cmd_get)"
          },
          "ep_cache_miss_rate": {
            unit: "percent",
            title: "cache miss ratio",
            desc: "Percentage of reads per second to this bucket from disk as opposed to RAM (measured from ep_bg_fetches / gets * 100)"
          },
          "ep_resident_items_rate": {
            unit: "percent",
            title: "resident %",
            desc: "Percentage of all items cached in RAM in this bucket (measured from ep_resident_items_rate)"
          },
          "vb_avg_active_queue_age": {
            unit: "second",
            title: "average active age",
            desc: "Average age in seconds of active items in the active item queue for this bucket (measured from vb_avg_active_queue_age)"
          },
          "vb_avg_replica_queue_age": {
            unit: "second",
            title: "average replica age",
            desc: "Average age in seconds of replica items in the replica item queue for this bucket (measured from vb_avg_replica_queue_age)"
          },
          "vb_avg_pending_queue_age": {
            unit: "second",
            title: "average pending age",
            desc: "Average age in seconds of pending items in the pending item queue for this bucket and should be transient during rebalancing (measured from vb_avg_pending_queue_age)"
          },
          "vb_avg_total_queue_age": {
            unit: "second",
            title: "average total age",
            desc: "Average age in seconds of all items in the disk write queue for this bucket (measured from vb_avg_total_queue_age)"
          },
          "vb_active_resident_items_ratio": {
            unit: "percent",
            title: "active docs resident %",
            desc: "Percentage of active items cached in RAM in this bucket (measured from vb_active_resident_items_ratio)"
          },
          "vb_replica_resident_items_ratio": {
            unit: "percent",
            title: "replica docs resident %",
            name: "vb_replica_resident_items_ratio",
            desc: "Percentage of replica items cached in RAM in this bucket (measured from vb_replica_resident_items_ratio)"
          },
          "vb_pending_resident_items_ratio": {
            unit: "percent",
            title: "pending docs resident %",
            desc: "Percentage of items in pending state vbuckets cached in RAM in this bucket (measured from vb_pending_resident_items_ratio)"
          },
          "avg_disk_update_time": {
            unit: "microsecond",
            title: "disk update time",
            desc: "Average disk update time in microseconds as from disk_update histogram of timings (measured from avg_disk_update_time)"
          },
          "avg_disk_commit_time": {
            unit: "percent",
            title: "disk commit time",
            desc: "Average disk commit time in seconds as from disk_update histogram of timings (measured from avg_disk_commit_time)"
          },
          "avg_bg_wait_time": {
            unit: "microsecond",
            title: "bg wait time",
            desc: "Average background fetch time in microseconds (measured from avg_bg_wait_time)"
          },
          "avg_active_timestamp_drift": {
            unit: "second",
            title: "avg active drift/mutation",
            name: "avg_active_timestamp_drift",
            desc: "Average drift (in seconds) per mutation on active vBuckets"
          },
          "avg_replica_timestamp_drift": {
            unit: "second",
            title: "avg replica drift/mutation",
            desc: "Average drift (in seconds) per mutation on replica vBuckets"
          },
          "ep_dcp_views+indexes_count": {
            unit: "number",
            title: "DCP connections",
            desc: "Number of internal views/indexes DCP connections in this bucket (measured from ep_dcp_views_count + ep_dcp_2i_count + ep_dcp_fts_count)"
          },
          "ep_dcp_views+indexes_items_remaining": {
            unit: "number",
            title: "items remaining",
            desc: "Number of items remaining to be sent to consumer in this bucket (measured from ep_dcp_views_items_remaining + ep_dcp_2i_items_remaining + ep_dcp_fts_items_remaining)"
          },
          "ep_dcp_views+indexes_producer_count": {
            unit: "number",
            title: "DCP senders",
            desc: "Number of views/indexes senders for this bucket (measured from ep_dcp_views_producer_count + ep_dcp_2i_producer_count + ep_dcp_fts_producer_count)"
          },
          "ep_dcp_views+indexes_total_backlog_size": null,
          "ep_dcp_views+indexes_items_sent": {
            unit: "number/sec",
            title: "drain rate items/sec",
            desc: "Number of items per second being sent for a producer for this bucket (measured from ep_dcp_views_items_sent + ep_dcp_2i_items_sent + ep_dcp_fts_items_sent)"
          },
          "ep_dcp_views+indexes_total_bytes": {
            unit: "bytes/sec",
            title: "drain rate bytes/sec",
            desc: "Number of bytes per second being sent for views/indexes DCP connections for this bucket (measured from ep_dcp_views_total_bytes + ep_dcp_2i_total_bytes + ep_dcp_fts_total_bytes)"
          },
          "ep_dcp_views+indexes_backoff": {
            unit: "number/sec",
            title: "backoffs/sec",
            desc: "Number of backoffs for views/indexes DCP connections (measured from ep_dcp_views_backoff + ep_dcp_2i_backoff + ep_dcp_fts_backoff)"
          },
          "bg_wait_count": null,
          "bg_wait_total": null,
          "bytes_read": {
            unit: "bytes/sec",
            name: "bytes_read",
            title: "bytes RX per sec.",
            desc: "Number of bytes per second sent into this bucket (measured from bytes_read)"
          },
          "bytes_written": {
            unit: "bytes/sec",
            title: "bytes TX per sec.",
            desc: "Number of bytes per second sent from this bucket (measured from bytes_written)"
          },
          "cas_badval": {
            unit: "number/sec",
            title: "CAS badval per sec.",
            desc: "Number of CAS operations per second using an incorrect CAS ID for data that this bucket contains (measured from cas_badval)"
          },
          "cas_hits": {
            unit: "number/sec",
            title: "CAS ops per sec.",
            desc: "Number of operations with a CAS id per second for this bucket (measured from cas_hits)"
            // memcached_stats_description
            // title: "CAS hits per sec.",
            // desc: "Number of CAS operations per second for data that this bucket contains (measured from cas_hits)"
          },
          "cas_misses": {
            unit: "number/sec",
            title: "CAS misses per sec.",
            desc: "Number of CAS operations per second for data that this bucket does not contain (measured from cas_misses)"
          },
          "cmd_get": {
            unit: "number/sec",
            title: "gets per sec.",
            desc: "Number of reads (get operations) per second from this bucket (measured from cmd_get)"
            // memcached_stats_description
            // title: "gets per sec.",
            // desc: "Number of get operations serviced by this bucket (measured from cmd_get)"
          },
          "cmd_set": {
            unit: "number/sec",
            title: "sets per sec.",
            desc: "Number of writes (set operations) per second to this bucket (measured from cmd_set)"
            // memcached_stats_description
            // title: "sets per sec.",
            // desc: "Number of set operations serviced by this bucket (measured from cmd_set)"
          },
          "couch_docs_actual_disk_size": {
            unit: "bytes",
            title: "docs total disk size",
            desc: "The size of all data files for this bucket, including the data itself, meta data and temporary files (measured from couch_docs_actual_disk_size)"
          },
          "couch_docs_data_size": {
            unit: "bytes",
            title: "docs data size",
            desc: "The size of active data in this bucket (measured from couch_docs_data_size)"
          },
          "couch_docs_disk_size": null,
          "couch_spatial_data_size": null,
          "couch_spatial_disk_size": null,
          "couch_spatial_ops": null,
          "couch_views_actual_disk_size": {
            unit: "bytes",
            title: "views total disk size",
            desc: "The size of all active items in all the indexes for this bucket on disk (measured from couch_views_actual_disk_size)"
          },
          "couch_views_data_size": {
            unit: "bytes",
            title: "views data size",
            desc: "The size of active data on for all the indexes in this bucket (measured from couch_views_data_size)"
          },
          "couch_views_disk_size": null,
          "couch_views_ops": {
            unit: "number/sec",
            title: "view reads per sec.",
            desc: "All the view reads for all design documents including scatter gather (measured from couch_views_ops)"
          },
          "curr_connections": {
            unit: "number/sec",
            title: "connections",
            desc: "Number of connections to this server including connections from external client SDKs, proxies, DCP requests and internal statistic gathering (measured from curr_connections)"
          },
          "curr_items": {
            unit: "number",
            title: "items",
            desc: "Number of unique items in this bucket - only active items, not replica (measured from curr_items)",
            //membase_vbucket_resources_stats_description
            //desc: "Number of items in \"active\" vBuckets in this bucket (measured from curr_items)"
            //memcached_stats_description
            //desc: "Number of items stored in this bucket (measured from curr_items)"
          },
          "curr_items_tot": {
            unit: "number",
            title: "items",
            desc: "Total number of items in this bucket (measured from curr_items_tot)"
          },
          "decr_hits": {
            unit: "number/sec",
            title: "decr hits per sec.",
            desc: "Number of decrement operations per second for data that this bucket contains (measured from decr_hits)"
          },
          "decr_misses": {
            unit: "number/sec",
            title: "decr misses per sec.",
            desc: "Number of decr operations per second for data that this bucket does not contain (measured from decr_misses)"
          },
          "delete_hits": {
            unit: "number/sec",
            title: "deletes per sec.",
            desc: "Number of delete operations per second for this bucket (measured from delete_hits)"
            //memcached_stats_description
            //title: "delete hits per sec.",
            //desc: "Number of delete operations per second for data that this bucket contains (measured from delete_hits)"
          },
          "delete_misses": {
            unit: "number/sec",
            title: "delete misses per sec.",
            desc: "Number of delete operations per second for data that this bucket does not contain (measured from delete_misses)"
          },
          "disk_commit_count": null,
          "disk_commit_total": null,
          "disk_update_count": null,
          "disk_update_total": null,
          "disk_write_queue": {
            unit: "number",
            title: "disk write queue",
            desc: "Number of items waiting to be written to disk in this bucket (measured from ep_queue_size+ep_flusher_todo)"
          },
          "ep_active_ahead_exceptions": {
            unit: "number/sec",
            title: "active ahead exceptions/sec",
            desc: "Total number of ahead exceptions for all active vBuckets"
          },
          "ep_active_hlc_drift": null,
          "ep_active_hlc_drift_count": null,
          "ep_bg_fetched": {
            unit: "number/sec",
            title: "disk reads per sec.",
            desc: "Number of reads per second from disk for this bucket (measured from ep_bg_fetched)"
          },
          "ep_clock_cas_drift_threshold_exceeded": null,
          "ep_data_read_failed": {
            unit: "number",
            title: "disk read failures.",
            desc: "Number of disk read failures (measured from ep_data_read_failed)"
          },
          "ep_data_write_failed": {
            unit: "number",
            title: "disk write failures.",
            desc: "Number of disk write failures (measured from ep_data_write_failed)"
          },
          "ep_dcp_2i_backoff": null,
          "ep_dcp_2i_count": null,
          "ep_dcp_2i_items_remaining": null,
          "ep_dcp_2i_items_sent": null,
          "ep_dcp_2i_producer_count": null,
          "ep_dcp_2i_total_backlog_size": null,
          "ep_dcp_2i_total_bytes": null,
          "ep_dcp_cbas_backoff": {
            unit: "number/sec",
            title: "backoffs/sec",
            desc: "Number of backoffs for analytics DCP connections (measured from ep_dcp_cbas_backoff)"
          },
          "ep_dcp_cbas_count": {
            unit: "number",
            title: "DCP connections",
            desc: "Number of internal analytics DCP connections in this bucket (measured from ep_dcp_cbas_count)"
          },
          "ep_dcp_cbas_items_remaining": {
            unit: "number",
            title: "items remaining",
            desc: "Number of items remaining to be sent to consumer in this bucket (measured from ep_dcp_cbas_items_remaining)"
          },
          "ep_dcp_cbas_items_sent": {
            unit: "number/sec",
            title: "drain rate items/sec",
            desc: "Number of items per second being sent for a producer for this bucket (measured from ep_dcp_cbas_items_sent)"
          },
          "ep_dcp_cbas_producer_count": {
            unit: "number",
            title: "DCP senders",
            desc: "Number of analytics senders for this bucket (measured from ep_dcp_cbas_producer_count)"
          },
          "ep_dcp_cbas_total_backlog_size": null,
          "ep_dcp_cbas_total_bytes": {
            unit: "bytes/sec",
            title: "drain rate bytes/sec",
            desc:"Number of bytes per second being sent for analytics DCP connections for this bucket (measured from ep_dcp_cbas_total_bytes)"
          },
          "ep_dcp_fts_backoff": null,
          "ep_dcp_fts_count": null,
          "ep_dcp_fts_items_remaining": null,
          "ep_dcp_fts_items_sent": null,
          "ep_dcp_fts_producer_count": null,
          "ep_dcp_fts_total_backlog_size": null,
          "ep_dcp_fts_total_bytes": null,
          "ep_dcp_other_backoff": {
            unit: "number/sec",
            title: "backoffs/sec",
            desc: "Number of backoffs for other DCP connections"
          },
          "ep_dcp_other_count": {
            unit: "number",
            title: "DCP connections",
            desc: "Number of other DCP connections in this bucket (measured from ep_dcp_other_count)"
          },
          "ep_dcp_other_items_remaining": {
            unit: "number",
            title: "items remaining",
            desc: "Number of items remaining to be sent to consumer in this bucket (measured from ep_dcp_other_items_remaining)"
          },
          "ep_dcp_other_items_sent": {
            unit: "number/sec",
            title: "drain rate items/sec",
            desc: "Number of items per second being sent for a producer for this bucket (measured from ep_dcp_other_items_sent)"
          },
          "ep_dcp_other_producer_count": {
            unit: "number",
            title: "DCP senders",
            desc: "Number of other senders for this bucket (measured from ep_dcp_other_producer_count)"
          },
          "ep_dcp_other_total_backlog_size": null,
          "ep_dcp_other_total_bytes": {
            unit: "bytes/sec",
            title: "drain rate bytes/sec",
            desc: "Number of bytes per second being sent for other DCP connections for this bucket (measured from ep_dcp_other_total_bytes)"
          },
          "ep_dcp_replica_backoff": {
            unit: "number",
            title: "backoffs/sec",
            desc: "Number of backoffs for replication DCP connections"
          },
          "ep_dcp_replica_count": {
            unit: "number",
            title: "DCP connections",
            desc: "Number of internal replication DCP connections in this bucket (measured from ep_dcp_replica_count)"
          },
          "ep_dcp_replica_items_remaining": {
            unit: "number",
            title: "intra-replication queue",
            desc: "Number of items remaining to be sent to consumer in this bucket (measured from ep_dcp_replica_items_remaining)",
            // membase_dcp_queues_stats_description
            // title: "items remaining",
            // desc: "Number of items remaining to be sent to consumer in this bucket (measured from ep_dcp_replica_items_remaining)"
          },
          "ep_dcp_replica_items_sent": {
            unit: "number",
            title: "drain rate items/sec",
            desc: "Number of items per second being sent for a producer for this bucket (measured from ep_dcp_replica_items_sent)"
          },
          "ep_dcp_replica_producer_count": {
            unit: "number",
            title: "DCP senders",
            desc: "Number of replication senders for this bucket (measured from ep_dcp_replica_producer_count)"
          },
          "ep_dcp_replica_total_backlog_size": null,
          "ep_dcp_replica_total_bytes": {
            unit: "bytes/sec",
            title: "drain rate bytes/sec",
            desc: "Number of bytes per second being sent for replication DCP connections for this bucket (measured from ep_dcp_replica_total_bytes)"
          },
          "ep_dcp_views_backoff": null,
          "ep_dcp_views_count": null,
          "ep_dcp_views_items_remaining": null,
          "ep_dcp_views_items_sent": null,
          "ep_dcp_views_producer_count": null,
          "ep_dcp_views_total_backlog_size": null,
          "ep_dcp_views_total_bytes": null,
          "ep_dcp_xdcr_backoff": {
            unit: "number",
            title: "backoffs/sec",
            desc: "Number of backoffs for xdcr DCP connections"
          },
          "ep_dcp_xdcr_count": {
            unit: "number",
            title: "DCP connections",
            desc: "Number of internal xdcr DCP connections in this bucket (measured from ep_dcp_xdcr_count)"
          },
          "ep_dcp_xdcr_items_remaining": {
            unit: "number",
            title: "items remaining",
            desc: "Number of items remaining to be sent to consumer in this bucket (measured from ep_dcp_xdcr_items_remaining)"
          },
          "ep_dcp_xdcr_items_sent": {
            unit: "number/sec",
            title: "drain rate items/sec",
            desc: "Number of items per second being sent for a producer for this bucket (measured from ep_dcp_xdcr_items_sent)"
          },
          "ep_dcp_xdcr_producer_count": {
            unit: "number",
            title: "DCP senders",
            desc: "Number of xdcr senders for this bucket (measured from ep_dcp_xdcr_producer_count)"
          },
          "ep_dcp_xdcr_total_backlog_size": null,
          "ep_dcp_xdcr_total_bytes": {
            unit: "bytes/sec",
            title: "drain rate bytes/sec",
            desc: "Number of bytes per second being sent for xdcr DCP connections for this bucket (measured from ep_dcp_xdcr_total_bytes)"
          },
          "ep_diskqueue_drain": {
            unit: "number/sec",
            title: "drain rate",
            desc: "Total number of items per second being written to disk in this bucket (measured from ep_diskqueue_drain)"
          },
          "ep_diskqueue_fill": {
            unit: "number/sec",
            title: "fill rate",
            desc: "Total number of items per second being put on the disk queue in this bucket (measured from ep_diskqueue_fill)"
          },
          "ep_diskqueue_items": {
            unit: "number",
            title: "items",
            desc: "Total number of items waiting to be written to disk in this bucket (measured from ep_diskqueue_items)"
          },
          "ep_flusher_todo": null,
          "ep_item_commit_failed": null,
          "ep_kv_size": {
            unit: "bytes",
            title: "user data in RAM",
            desc: "Total amount of user data cached in RAM in this bucket (measured from ep_kv_size)"
          },
          "ep_max_size": null,
          "ep_mem_high_wat": {
            unit: "bytes",
            title: "high water mark",
            desc: "High water mark for auto-evictions (measured from ep_mem_high_wat)"
          },
          "ep_mem_low_wat": {
            unit: "bytes",
            title: "low water mark",
            desc: "Low water mark for auto-evictions (measured from ep_mem_low_wat)"
          },
          "ep_meta_data_memory": {
            unit: "bytes",
            title: "metadata in RAM",
            desc: "Total amount of item metadata consuming RAM in this bucket (measured from ep_meta_data_memory)"
          },
          "ep_num_non_resident": null,
          "ep_num_ops_del_meta": {
            unit: "number/sec",
            title: "deletes per sec.",
            desc: "Number of delete operations per second for this bucket as the target for XDCR (measured from ep_num_ops_del_meta)"
          },
          "ep_num_ops_del_ret_meta": null,
          "ep_num_ops_get_meta": {
            unit: "number/sec",
            title: "metadata reads per sec.",
            desc: "Number of metadata read operations per second for this bucket as the target for XDCR (measured from ep_num_ops_get_meta)"
          },
          "ep_num_ops_set_meta": {
            unit: "number/sec",
            title: "sets per sec.",
            desc: "Number of set operations per second for this bucket as the target for XDCR (measured from ep_num_ops_set_meta)"
          },
          "ep_num_ops_set_ret_meta": null,
          "ep_num_value_ejects": {
            unit: "number/sec",
            title: "ejections per sec.",
            desc: "Total number of items per second being ejected to disk in this bucket (measured from ep_num_value_ejects)"
          },
          "ep_oom_errors": null,
          "ep_ops_create": {
            unit: "number/sec",
            title: "disk creates per sec.",
            desc: "Number of new items created on disk per second for this bucket (measured from vb_active_ops_create + vb_replica_ops_create + vb_pending_ops_create)"
            // membase_vbucket_resources_stats_description
            // title: "new items per sec.",
            // desc: "Total number of new items being inserted into this bucket (measured from ep_ops_create)"
          },
          "ep_ops_update": {
            unit: "number/sec",
            title: "disk updates per sec.",
            desc: "Number of items updated on disk per second for this bucket (measured from vb_active_ops_update + vb_replica_ops_update + vb_pending_ops_update)"
          },
          "ep_overhead": null,
          "ep_queue_size": null,
          "ep_replica_ahead_exceptions": {
            unit: "number",
            title: "replica ahead exceptions/sec",
            desc: "Total number of ahead exceptions for all replica vBuckets"
          },
          "ep_replica_hlc_drift": null,
          "ep_replica_hlc_drift_count": null,
          "ep_tmp_oom_errors": {
            unit: "number/sec",
            title: "temp OOM per sec.",
            desc: "Number of back-offs sent per second to client SDKs due to \"out of memory\" situations from this bucket (measured from ep_tmp_oom_errors)"
          },
          "ep_vb_total": {
            unit: "number",
            title: "vBuckets",
            desc: "Total number of vBuckets for this bucket (measured from ep_vb_total)",
          },
          "evictions": {
            unit: "number/sec",
            title: "evictions per sec.",
            desc: "Number of items per second evicted from this bucket (measured from evictions)"
          },
          "get_hits": {
            unit: "number/sec",
            title: "get hits per sec.",
            desc: "Number of get operations per second for data that this bucket contains (measured from get_hits)"
          },
          "get_misses": {
            unit: "number/sec",
            title: "get misses per sec.",
            desc: "Number of get operations per second for data that this bucket does not contain (measured from get_misses)",
          },
          "incr_hits": {
            unit: "number/sec",
            title: "incr hits per sec.",
            desc: "Number of increment operations per second for data that this bucket contains (measured from incr_hits)"
          },
          "incr_misses": {
            unit: "number/sec",
            title: "incr misses per sec.",
            desc: "Number of increment operations per second for data that this bucket does not contain (measured from incr_misses)"
          },
          "mem_used": {
            unit: "bytes",
            title: "memory used",
            desc: "Memory used as measured from mem_used"
            // memcached_stats_description
            // isBytes: true
            // title: "RAM used",
            // desc: "Total amount of RAM used by this bucket (measured from mem_used)"
          },
          "misses": null,
          "ops": {
            unit: "number/sec",
            title: "ops per second",
            desc: "Total amount of operations per second (including XDCR) to this bucket (measured from cmd_get + cmd_set + incr_misses + incr_hits + decr_misses + decr_hits + delete_misses + delete_hits + ep_num_ops_del_meta + ep_num_ops_get_meta + ep_num_ops_set_meta)"
            // memcached_stats_description
            // title: "ops per sec.",
            // default: true,
            // desc: "Total operations per second serviced by this bucket (measured from cmd_get + cmd_set + incr_misses + incr_hits + decr_misses + decr_hits + delete_misses + delete_hits + get_meta + set_meta + delete_meta)"
          },
          "vb_active_eject": {
            unit: "number/sec",
            title: "ejections per sec.",
            desc: "Number of items per second being ejected to disk from \"active\" vBuckets in this bucket (measured from vb_active_eject)"
          },
          "vb_active_itm_memory": {
            unit: "bytes",
            title: "user data in RAM",
            desc: "Amount of active user data cached in RAM in this bucket (measured from vb_active_itm_memory)"
          },
          "vb_active_meta_data_memory": {
            unit: "bytes",
            title: "metadata in RAM",
            desc: "Amount of active item metadata consuming RAM in this bucket (measured from vb_active_meta_data_memory)"
          },
          "vb_active_num": {
            unit: "bytes",
            title: "vBuckets",
            desc: "Number of vBuckets in the \"active\" state for this bucket (measured from vb_active_num)"
          },
          "vb_active_num_non_resident": null,
          "vb_active_ops_create": {
            unit: "number/sec",
            title: "new items per sec.",
            desc: "New items per second being inserted into \"active\" vBuckets in this bucket (measured from vb_active_ops_create)"
          },
          "vb_active_ops_update": null,
          "vb_active_queue_age": null,
          "vb_active_queue_drain": {
            unit: "number/sec",
            title: "drain rate",
            desc: "Number of active items per second being written to disk in this bucket (measured from vb_active_queue_drain)"
          },
          "vb_active_queue_fill": {
            unit: "number/sec",
            title: "fill rate",
            desc: "Number of active items per second being put on the active item disk queue in this bucket (measured from vb_active_queue_fill)"
          },
          "vb_active_queue_size": {
            unit: "number",
            title: "active items",
            desc: "Number of active items waiting to be written to disk in this bucket (measured from vb_active_queue_size)"
          },
          "vb_pending_curr_items": {
            unit: "number",
            title: "pending items",
            desc: "Number of items in \"pending\" vBuckets in this bucket and should be transient during rebalancing (measured from vb_pending_curr_items)"
          },
          "vb_pending_eject": {
            unit: "number/sec",
            title: "ejections per sec.",
            desc: "Number of items per second being ejected to disk from \"pending\" vBuckets in this bucket and should be transient during rebalancing (measured from vb_pending_eject)"
          },
          "vb_pending_itm_memory": {
            unit: "bytes",
            title: "user data in RAM",
            desc: "Amount of pending user data cached in RAM in this bucket and should be transient during rebalancing (measured from vb_pending_itm_memory)"
          },
          "vb_pending_meta_data_memory": {
            unit: "bytes",
            title: "metadata in RAM",
            desc: "Amount of pending item metadata consuming RAM in this bucket and should be transient during rebalancing (measured from vb_pending_meta_data_memory)"
          },
          "vb_pending_num": {
            unit: "number",
            title: "vBuckets",
            desc: "Number of vBuckets in the \"pending\" state for this bucket and should be transient during rebalancing (measured from vb_pending_num)"
          },
          "vb_pending_num_non_resident": null,
          "vb_pending_ops_create": {
            unit: "number/sec",
            title: "new items per sec.",
            desc: "New items per second being instead into \"pending\" vBuckets in this bucket and should be transient during rebalancing (measured from vb_pending_ops_create)"
          },
          "vb_pending_ops_update": null,
          "vb_pending_queue_age": null,
          "vb_pending_queue_drain": {
            unit: "number/sec",
            title: "drain rate",
            desc: "Number of pending items per second being written to disk in this bucket and should be transient during rebalancing (measured from vb_pending_queue_drain)"
          },
          "vb_pending_queue_fill": {
            unit: "number/sec",
            title: "fill rate",
            desc: "Number of pending items per second being put on the pending item disk queue in this bucket and should be transient during rebalancing (measured from vb_pending_queue_fill)"
          },
          "vb_pending_queue_size": {
            unit: "number",
            title: "items",
            desc: "Number of pending items waiting to be written to disk in this bucket and should be transient during rebalancing  (measured from vb_pending_queue_size)"
          },
          "vb_replica_curr_items": {
            unit: "number",
            title: "items in replica",
            desc: "Number of items in \"replica\" vBuckets in this bucket (measured from vb_replica_curr_items)"
          },
          "vb_replica_eject": {
            unit: "number/sec",
            title: "ejections per sec.",
            desc: "Number of items per second being ejected to disk from \"replica\" vBuckets in this bucket (measured from vb_replica_eject)"
          },
          "vb_replica_itm_memory": {
            unit: "bytes",
            title: "user data in RAM",
            desc: "Amount of replica user data cached in RAM in this bucket (measured from vb_replica_itm_memory)"
          },
          "vb_replica_meta_data_memory": {
            unit: "bytes",
            title: "metadata in RAM",
            desc: "Amount of replica item metadata consuming in RAM in this bucket (measured from vb_replica_meta_data_memory)"
          },
          "vb_replica_num": {
            unit: "number",
            title: "vBuckets",
            desc: "Number of vBuckets in the \"replica\" state for this bucket (measured from vb_replica_num)"
          },
          "vb_replica_num_non_resident": null,
          "vb_replica_ops_create": {
            unit: "number/sec",
            title: "new items per sec.",
            desc: "New items per second being inserted into \"replica\" vBuckets in this bucket (measured from vb_replica_ops_create"
          },
          "vb_replica_ops_update": null,
          "vb_replica_queue_age": null,
          "vb_replica_queue_drain": {
            unit: "number/sec",
            title: "drain rate",
            desc: "Number of replica items per second being written to disk in this bucket (measured from vb_replica_queue_drain)"
          },
          "vb_replica_queue_fill": {
            unit: "number/sec",
            title: "fill rate",
            desc: "Number of replica items per second being put on the replica item disk queue in this bucket (measured from vb_replica_queue_fill)"
          },
          "vb_replica_queue_size": {
            unit: "number",
            title: "items",
            desc: "Number of replica items waiting to be written to disk in this bucket (measured from vb_replica_queue_size)"
          },
          "vb_total_queue_age": null,
          "xdc_ops": {
            unit: "number/sec",
            title: "incoming XDCR ops/sec.",
            desc: "Incoming XDCR operations per second for this bucket (measured from xdc_ops)"

            // membase_incoming_xdcr_operations_stats_description
            // title: "total ops per sec.",
            // desc: "Total XDCR operations per second for this bucket (measured from ep_num_ops_del_meta + ep_num_ops_get_meta + ep_num_ops_set_meta)"
          },
          "@items": {
            "accesses": {
              unit: "number/sec",
              title: "view reads per sec.",
              desc: "Traffic to the views in this design doc"
            },
            "data_size": {
              unit: "bytes",
              title: "data size",
              desc: "How many bytes stored"
            },
            "disk_size": {
              unit: "bytes",
              title: "disk size",
              desc: "How much storage used"
            }
          }
        },
        "@system":{
          "cpu_cores_available": null,
          "cpu_idle_ms": null,
          "cpu_local_ms": null,
          "cpu_utilization_rate": {
            unit: "percent",
            title: "Max CPU utilization %",
            desc: "Percentage of CPU in use across all available cores on this server",
          },
          "hibernated_requests": {
            unit: "number",
            title: "idle streaming requests",
            desc: "Number of streaming requests on management port (usually, 8091) now idle"
          },
          "hibernated_waked": {
            unit: "number/sec",
            title: "streaming wakeups/sec",
            desc: "Rate of streaming request wakeups on management port (usually, 8091)"
          },
          "mem_actual_free": {
            unit: "bytes",
            title: "free RAM",
            desc: "Amount of RAM available on this server"
          },
          "mem_actual_used": null,
          "mem_free": null,
          "mem_limit": null,
          "mem_total": null,
          "mem_used_sys": null,
          "rest_requests": {
            unit: "number/sec",
            title: "Management port reqs/sec",
            desc: "Rate of http requests on management port (usually, 8091)"
          },
          "swap_total": null,
          "swap_used": {
            unit: "bytes",
            title: "swap usage",
            desc: "Amount of swap space in use on this server"
          },
        },
        "@cbas-":{
          "cbas/failed_at_parser_records_count": null,
          "cbas/failed_at_parser_records_count_total": {
            unit: "number",
            title: "sync failed records",
            desc: "Failed to parse records during bucket synchronization"
          },
          "cbas/incoming_records_count": {
            unit: "number/sec",
            title: "ops/sec.",
            desc: "Operations (gets + sets + deletes) per second processed by Analytics for this bucket"
          },
          "cbas/incoming_records_count_total": {
            unit: "number",
            title: "total ops since bucket connect",
            desc: "Operations (gets + sets + deletes) processed by Analytics for this bucket since last connected"
          }
        },
        "@index-":{
          "@items": {
            "avg_item_size": {
              unit: "bytes",
              title: "average item size",
              desc: "Average size of each index item"
            },
            "avg_scan_latency": {
              unit: "nanoseconds",
              title: "avg scan latency(ns)",
              desc: "Average time to serve a scan request (nanoseconds)"
            },
            "cache_hits": null,
            "cache_miss_ratio": {
              unit: "percent",
              title: "index cache miss ratio",
              desc: "Percentage of accesses to this index data from disk as opposed to RAM (measured from cache_misses * 100 / (cache_misses + cache_hits))"
            },
            "cache_misses": null,
            "data_size": {
              unit: "bytes",
              title: "data size",
              desc: "Actual data size consumed by the index"
              //membase_index_stats_description
              //title: "index data size"
            },
            "disk_overhead_estimate": null,
            "disk_size": {
              unit: "bytes",
              title: "disk size",
              desc: "Total disk file size consumed by the index"
            },
            "frag_percent": null,
            "index_frag_percent": {
              unit: "percent",
              title: "% fragmentation",
              desc: "Percentage fragmentation of the index. Note: at small index sizes of less than a hundred kB, the static overhead of the index disk file will inflate the index fragmentation percentage"
            },
            "index_resident_percent": {
              unit: "percent",
              title: "cache resident percent",
              desc: "Percentage of index data resident in memory"
            },
            "items_count": {
              unit: "number",
              title: "total indexed items",
              desc: "Current total indexed document count"
            },
            "memory_used": {
              unit: "bytes",
              title: "memory used",
              desc: "Total memory consumed by the index storage"
            },
            "num_docs_indexed": {
              unit: "number/sec",
              title: "drain rate items/sec",
              desc: "Number of documents indexed by the indexer per second"
            },
            "num_docs_pending": null,
            "num_docs_pending+queued": {
              unit: "number",
              title: "total mutations remaining",
              desc: "Number of documents pending to be indexed"
            },
            "num_docs_queued": null,
            "num_requests": {
              unit: "number/sec",
              title: "requests/sec",
              desc: "Number of requests served by the indexer per second"
            },
            "num_rows_returned": {
              unit: "number/sec",
              title: "items scanned/sec",
              desc: "Number of index items scanned by the indexer per second"
            },
            "recs_in_mem": null,
            "recs_on_disk": null,
            "scan_bytes_read": {
              unit: "number/sec",
              title: "bytes returned/sec",
              desc: "Number of bytes per second read by a scan"
            },
            "total_scan_duration": null,
          },
          "index/cache_hits": null,
          "index/cache_misses": null,
          "index/data_size": {
            unit: "bytes",
            title: "index data size",
            desc: "Actual data size consumed by the index"
          },
          "index/disk_overhead_estimate": null,
          "index/disk_size": {
            unit: "bytes",
            title: "disk size",
            desc: "Total disk file size consumed by the index"
          },
          "index/frag_percent": null,
          "index/fragmentation": {
            unit: "percent",
            title: "index fragmentation %",
            desc: "Percentage fragmentation of the index. Note: at small index sizes of less than a hundred kB, the static overhead of the index disk file will inflate the index fragmentation percentage"
          },
          "index/cache_hits": null,
          "index/cache_misses": null,
          "index/items_count": null,
          "index/memory_used": null,
          "index/num_docs_indexed": null,
          "index/num_docs_pending": null,
          "index/num_docs_queued": null,
          "index/num_requests": null,
          "index/num_rows_returned": {
            unit: "number/sec",
            title: "index scanned/sec",
            desc: "Number of index items scanned by the indexer per second"
          },
          "index/recs_in_mem": null,
          "index/recs_on_disk": null,
          "index/scan_bytes_read": null,
          "index/total_scan_duration": null
        },
        "@eventing":{},
        "@cbas":{
          "cbas_disk_used": {
            unit: "bytes",
            title: "analytics total disk size",
            desc: "The total disk size used by Analytics"
          },
          "cbas_gc_count": {
            unit: "number",
            title: "analytics gc count/sec",
            desc: "Number of JVM garbage collections for Analytics node"
          },
          "cbas_gc_time": {
            unit: "millisecond/sec",
            title: "analytics gc time (ms.)/sec",
            desc: "The amount of time in milliseconds spent performing JVM garbage collections for Analytics node"
          },
          "cbas_heap_used": {
            unit: "bytes",
            title: "analytics heap used",
            desc: "Amount of JVM heap used by Analytics on this server"
          },
          "cbas_system_load_average": {
            unit: "bytes",
            title: "analytics system load",
            desc: "System load for Analytics node"
          },
          "cbas_thread_count": {
            unit: "number",
            title: "analytics thread count",
            desc: "Number of threads for Analytics node"
          }
        },
        "@index":{
          "index_memory_quota": null,
          "index_memory_used": null,
          "index_ram_percent": {
            unit: "percent",
            title: "Max Index RAM Used %",
            desc: "Percentage of Index RAM in use across all indexes on this server"
          },
          "index_remaining_ram": {
            unit: "number",
            title: "remaining index ram",
            desc: "Amount of index RAM available on this server"
          }
        },
        "@query":{
          "query_avg_req_time": {
            unit: "second",
            title: "request time(sec)",
            desc: "Average end-to-end time to process a query (in seconds)"
          },
          "query_avg_svc_time": {
            unit: "second",
            title: "service time(sec)",
            desc: "Average time to execute a query (in seconds)"
          },
          "query_avg_response_size": {
            unit: "bytes",
            title: "result size",
            desc: "Average size (in bytes) of the data returned by a query"
          },
          "query_avg_result_count": {
            unit: "number",
            title: "result count",
            desc: "Average number of results (documents) returned by a query"
          },
          "query_active_requests": null,
          "query_errors": {
            unit: "number/sec",
            title: "errors",
            desc: "Number of N1QL errors returned per second"
          },
          "query_invalid_requests": {
            unit: "number/sec",
            title: "invalid requests/sec",
            desc: "Number of requests for unsupported endpoints per second, specifically HTTP requests for all endpoints not supported by the query engine. For example, a request for http://localhost:8093/foo will be included. Potentially useful in identifying DOS attacks."
          },
          "query_queued_requests": null,
          "query_request_time": null,
          "query_requests": {
            unit: "number/sec",
            title: "requests/sec",
            desc: "Number of N1QL requests processed per second"
            // membase_query_stats_description
            // title: "N1QL queries/sec"
            // desc: "Number of N1QL requests processed per second"
          },
          "query_requests_1000ms": {
            unit: "number/sec",
            title: "queries > 1000ms",
            desc: "Number of queries that take longer than 1000 ms per second"
          },
          "query_requests_250ms": {
            unit: "number/sec",
            title: "queries > 250ms",
            desc: "Number of queries that take longer than 250 ms per second"
          },
          "query_requests_5000ms": {
            unit: "number/sec",
            title: "queries > 5000ms",
            desc: "Number of queries that take longer than 5000 ms per second"
          },
          "query_requests_500ms": {
            unit: "number/sec",
            title: "queries > 500ms",
            desc: "Number of queries that take longer than 500 ms per second"
          },
          "query_result_count": null,
          "query_result_size": null,
          "query_selects": {
            unit: "number/sec",
            title: "selects/sec",
            desc: "Number of N1QL selects processed per second"
          },
          "query_service_time": null,
          "query_warnings": {
            unit: "number/sec",
            title: "warnings",
            desc: "Number of N1QL errors returned per second"
          }
        },
        "@xdcr-":{
          "replication_changes_left": {
            unit: "number/sec",
            title: "outbound XDCR mutations",
            desc: "Number of mutations to be replicated to other clusters (measured from replication_changes_left)"
          },
          "replication_docs_rep_queue": null,
          "@items": {
            "percent_completeness": {
              unit: "percent",
              title: "percent completed",
              desc: "Percentage of checked items out of all checked and to-be-replicated items (measured from per-replication stat percent_completeness)"
            },
            "bandwidth_usage": {
              unit: "bytes/sec",
              title: "data replication rate",
              desc: "Rate of replication in terms of bytes replicated per second (measured from per-replication stat bandwidth_usage)"
            },
            "changes_left": {
              unit: "number",
              title: "mutations",
              desc: "Number of mutations to be replicated to other clusters (measured from per-replication stat changes_left)"
            },
            "data_replicated": null,
            "dcp_datach_length": null,
            "dcp_dispatch_time": null,
            "deletion_docs_written": null,
            "deletion_failed_cr_source": null,
            "deletion_filtered": null,
            "deletion_received_from_dcp": null,
            "docs_checked": null,
            "docs_failed_cr_source": {
              unit: "number",
              title: "mutations skipped by resolution",
              desc: "Number of mutations that failed conflict resolution on the source side and hence have not been replicated to other clusters (measured from per-replication stat docs_failed_cr_source)"
            },
            "docs_filtered": {
              unit: "number/sec",
              title: "mutations filtered per sec.",
              desc: "Number of mutations per second that have been filtered out and have not been replicated to other clusters (measured from per-replication stat docs_filtered)"
            },
            "docs_opt_repd": null,
            "docs_processed": null,
            "docs_received_from_dcp": null,
            "docs_rep_queue": null,
            "docs_written": {
              unit: "number",
              title: "mutations replicated",
              desc: "Number of mutations that have been replicated to other clusters (measured from per-replication stat docs_written)"
            },
            "expiry_docs_written": null,
            "expiry_failed_cr_source": null,
            "expiry_filtered": null,
            "expiry_received_from_dcp": null,
            "num_checkpoints": null,
            "num_failedckpts": null,
            "rate_doc_checks": {
              unit: "number/sec",
              title: "doc checks rate",
              desc: "Rate of doc checks per second "
            },
            "rate_doc_opt_repd": {
              unit: "number/sec",
              title: "opt. replication rate",
              desc: "Rate of optimistic replications in terms of number of replicated mutations per second "
            },
            "rate_received_from_dcp": {
              unit: "number/sec",
              title: "doc reception rate",
              desc: "Rate of mutations received from dcp in terms of number of mutations per second"
            },
            "rate_replicated": {
              unit: "number/sec",
              title: "mutation replication rate",
              desc:"Rate of replication in terms of number of replicated mutations per second (measured from per-replication stat rate_replicated)"
            },
            "resp_wait_time": null,
            "set_docs_written": null,
            "set_failed_cr_source": null,
            "set_filtered": null,
            "set_received_from_dcp": null,
            "size_rep_queue": null,
            "throttle_latency": null,
            "time_committing": null,
            "wtavg_docs_latency": {
              unit: "millisecond",
              title: "ms doc batch latency",
              desc: "Weighted average latency in ms of sending replicated mutations to remote cluster (measured from per-replication stat wtavg_docs_latency)"
            },
            "wtavg_meta_latency": {
              unit: "millisecond",
              title: "ms meta batch latency",
              desc: "Weighted average latency in ms of sending getMeta and waiting for conflict solution result from remote cluster (measured from per-replication stat wtavg_meta_latency)"
            }
          }
        },
        "@fts-": {
          "@items": {
            "avg_queries_latency": {
              unit: "millisecond",
              title: "avg query latency(ms)",
              desc: "Average time to answer query (measured from avg_queries_latency)"
            },
            "doc_count": {
              unit: "number",
              title: "items",
              desc: "Number of documents (measured from doc_count)"
            },
            "num_bytes_used_disk": {
              unit: "bytes",
              title:"disk size",
              desc: "Total disk file size used by the index (measured from num_bytes_used_disk)"
            },
            "num_mutations_to_index": {
              unit: "number",
              title: "items remaining",
              desc: "Number of mutations not yet indexed (measured from num_mutations_to_index)"
            },
            "num_pindexes_actual": {
              unit: "number",
              title: "partitions actual",
              desc: "Number of index partitions (including replica partitions, measured from num_pindexes_actual)"
            },
            "num_pindexes_target": {
              unit: "number",
              title: "partitions target",
              desc: "Number of index partitions expected (including replica partitions, measured from num_pindexes_target)"
            },
            "num_recs_to_persist": {
              unit: "number",
              title: "records to persist",
              desc: "Number of index records not yet persisted to disk (measured from num_recs_to_persist)"
            },
            "total_bytes_indexed": {
              unit: "bytes/sec",
              title: "bytes indexed/sec",
              desc: "Number of plain text bytes indexed per second (measured from total_bytes_indexed)"
            },
            "total_bytes_query_results": {
              unit: "bytes/sec",
              title: "bytes returned/sec",
              desc: "Number of bytes returned in results per second (measured from total_bytes_query_results)"
            },
            "total_compaction_written_bytes": {
              unit: "bytes/sec",
              title: "compaction bytes written/sec",
              desc: "Number of compaction bytes written per second (measured from total_compaction_written_bytes)",
            },
            "total_queries": {
              unit: "number/sec",
              title: "queries/sec",
              desc: "Number of queries per second (measured from total_queries)"
            },
            "total_queries_error": {
              unit: "number/sec",
              title: "error queries/sec",
              desc: "Number of queries that resulted in errors per second. Includes timeouts (measured from total_queries_error)"
            },
            "total_queries_slow": {
              unit: "number/sec",
              title: "slow queries/sec",
              desc: "Number of slow queries per second (measured from total_queries_slow - those taking > 5s to run)"
            },
            "total_queries_timeout": {
              unit: "number/sec",
              title: "timeout queries/sec",
              desc: "Number of queries that timeout per second (measured from total_queries_timeout)"
            },
            "total_request_time": null,
            "total_term_searchers": {
              unit: "number/sec",
              title: "term searchers/sec",
              desc: "Number of term searchers started per second (measured from total_term_searchers)"
            },
          },
          "fts/doc_count": null,
          "fts/num_bytes_used_disk": {
            unit: "bytes",
            title: "fts disk size",
            desc: "Total fts disk file size for this bucket"
          },
          "fts/num_mutations_to_index": null,
          "fts/num_pindexes_actual": null,
          "fts/num_pindexes_target": null,
          "fts/num_recs_to_persist": null,
          "fts/total_bytes_indexed": {
            unit: "bytes/sec",
            title: "fts bytes indexed/sec",
            desc: "Number of fts bytes indexed per second"
          },
          "fts/total_bytes_query_results": null,
          "fts/total_compaction_written_bytes": null,
          "fts/total_queries": {
            unit: "number/sec",
            title: "fts queries/sec",
            desc: "Number of fts queries per second"
          },
          "fts/total_queries_error": null,
          "fts/total_queries_slow": null,
          "fts/total_queries_timeout": null,
          "fts/total_request_time": null,
          "fts/total_term_searchers": null
        },
        "@fts": {
          "fts_num_bytes_used_ram": {
            unit: "bytes",
            title: "fts RAM used",
            desc: "Amount of RAM used by FTS on this server"
          }
        }
      }
    }
  }
})();
