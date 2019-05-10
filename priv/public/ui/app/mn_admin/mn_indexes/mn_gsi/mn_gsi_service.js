(function () {
  "use strict";

  angular.module('mnGsiService', ["qwQuery"]).factory('mnGsiService', mnGsiServiceFactory);

  function mnGsiServiceFactory($http, $q, qwQueryService, mnAnalyticsService) {
    var mnGsiService = {
      getIndexesState: getIndexesState,
      postDropIndex: postDropIndex
    };

    return mnGsiService;

    function postDropIndex(row) {
      // to drop an index, we create a 'DROP' query to send to the query workbench
      return qwQueryService
        .executeQueryUtil('DROP INDEX `' + row.bucket + '`.`' + row.index + '`', true);
    }

    function getIndexesState(mnHttpParams,forController) {
      return $http({
        method: 'GET',
        url: '/indexStatus',
        mnHttp: mnHttpParams
      }).then(function success(resp) {
        var byNodes = {};
        var byBucket = {};
        var byID = {};

        resp.data.indexes.forEach(function (index) {
          index.hosts.forEach(function (node) {
            byNodes[node] = byNodes[node] || [];
            byNodes[node].push(index);
          });

          byBucket[index.bucket] = byBucket[index.bucket] || [];
          byBucket[index.bucket].push(index);
        });

        resp.data.byBucket = byBucket;
        resp.data.byNodes = byNodes;
        resp.data.byID = resp.data.indexes;

        if (forController) // only get stats for indexes if we're being called by the gsi_controller
          return getAllIndexStats(resp.data);
        else
          return(resp.data);
      });
    }

    //
    // make a single call to get all stats, and pull out the ones we want for our indexes
    function getAllIndexStats(state) {
      var index_stat_names = ["data_size","num_rows_returned","index_resident_percent","num_docs_pending+queued","num_requests"];

      var stat_names = {
          "@index": ["index_memory_quota","index_memory_used","index_ram_percent","index_remaining_ram"],
          "@kv-": ["ep_dcp_views+indexes_count","ep_dcp_views+indexes_items_remaining","ep_dcp_views+indexes_producer_count","ep_dcp_views+indexes_total_backlog_size","ep_dcp_views+indexes_total_bytes","ep_dcp_views+indexes_backoff"],
          "@index-": ["index/fragmentation","index/memory_used","index/disk_size","index/data_size"]
        };


      var promises = [];
      var bucket_names = Object.keys(state.byBucket);
      bucket_names.forEach(function(bucket_name) {               // for each bucket
        promises.push(
            mnAnalyticsService.getStats({$stateParams:{
              bucket: bucket_name,
              statsHostname: "all",
              zoom: "minute"
            }})
            .then(function success(data) {
              var result = {};
              if (data && data.statsByName) {
                state.byBucket[bucket_name].forEach(function(index) { // for each index in the bucket
                  index_stat_names.forEach(function(stat_name) {         // for each statistic
                    var fullName = 'index/' + index.index + '/' + stat_name;
                    var stats = data.statsByName[fullName].config.data.slice(-5); // only want last 5 secs of data
                    result[fullName] =  stats.reduce(function (sum, stat) {return sum + stat;}, 0) / stats.length;
                  });
                });
                // get the overall stats for this bucket
                result.overall = result.overall || {};
                result.overall[bucket_name] = {};try {
                Object.keys(stat_names).forEach(function (section) {
                  var section1 = section.includes("-") ? (section + bucket_name) : section;
                  stat_names[section].forEach(function (statName) {
                    var stats = data.stats.stats[section1][statName].slice(-5); // only want last 5 seconds
                    result.overall[bucket_name][statName] = stats.reduce(function (sum, stat) {
                      return sum + stat;
                    }, 0) / stats.length;
                  });
                });
                } catch (e) {console.log("Got error: " + e)}
                return(result);
              }
            },function error(resp) {return(state);})
        );
      });

      // got stats for every bucket with indexes, now process the results
      return $q.all(promises).then(function(values) {
        var index_stats = {};
        var overall_stats = {};
        values.forEach(function(some_stats) {
          if (some_stats.overall)
            Object.assign(overall_stats,some_stats.overall);
          Object.assign(index_stats,some_stats);
        });

        state.overall_stats = overall_stats;

        // add the values for each stat to each index
        state.byID.forEach(function (index) {
          index_stat_names.forEach(function(stat_name) {         // for each statistic
            index[stat_name] = index_stats['index/' + index.index + '/' + stat_name];
          });
        });
        return(state);
      });


    }
  }
})();
