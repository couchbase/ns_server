(function () {
  "use strict";

  angular
    .module('mnStatisticsNewService', ["mnServersService", 'mnPoll', "mnStatisticsDescriptionService", "mnHelper"])
    .factory('mnStatisticsNewService', mnStatisticsNewServiceFactory);

  function mnStatisticsNewServiceFactory($http, $q, mnServersService, mnPoller, $rootScope, mnStatisticsDescriptionService, mnHelper, mnStoreService) {
    var mnStatisticsNewService = {
      prepareNodesList: prepareNodesList,
      export: {
        scenario: {}
      },
      doGetStats: doGetStats,
      getStatSourcePath: getStatSourcePath,
      subscribeUIStatsPoller: subscribeUIStatsPoller,
      unsubscribeUIStatsPoller: unsubscribeUIStatsPoller,

      copyScenario: copyScenario,
      deleteScenario: deleteScenario,
      deleteGroup: deleteGroup,
      deleteChart: deleteChart,
      doAddPresetScenario: doAddPresetScenario,

      getStatsDirectory: getStatsDirectory,
      readByPath: readByPath,
      getStatsV2: getStatsV2,
      getStatsUnits: getStatsUnits,
      getStatsTitle: getStatsTitle,
      getStatsDesc: getStatsDesc,
      tickMultiFormat: d3.time.format.multi([
        ["%-I:%M:%S%p", function (d) {return d.getSeconds(); }],
        ["%-I:%M%p", function (d) {return d.getMinutes(); }], // not the beginning of the hour
        ["%-I%p", function (d) { return d.getHours(); }], // not midnight
        ["%b %-d", function (d) { return d.getDate() != 1; }], // not the first of the month
        ["%b %-d", function (d) { return d.getMonth(); }], // not Jan 1st
        ["%Y", function () { return true; }]
      ])
    };

    var pollers = {};
    var uiStatsScopes = {};
    var rootScopes = {};

    return mnStatisticsNewService;

    function getStatsDirectory(bucket, params) {
      //we are using this end point in new stats ui in order to tie ddocs names with ddocs stats
      //via ddocs signatures
      params = params || {
        adde: '"all"',
        adda: '"all"',
        addi: '"all"',
        addf: '"all"',
        addq: "1"
      };
      return $http({
        url: "/pools/default/buckets//" + bucket + "/statsDirectory",
        method: 'GET',
        params: params
      });
    }

    function deleteChart(chartID) {
      var group = mnStoreService.store("groups").getByIncludes(chartID, "charts");
      group.charts.splice(group.charts.indexOf(chartID), 1);
      mnStoreService.store("charts").delete(chartID);
    }

    function deleteGroup(groupID) {
      var scenario = mnStoreService.store("scenarios").getByIncludes(groupID, "groups");
      scenario.groups.splice(scenario.groups.indexOf(groupID), 1);
      var group = mnStoreService.store("groups").get(groupID);
      group.charts.forEach(function (chartID) {
        mnStoreService.store("charts").delete(chartID);
      });
      mnStoreService.store("groups").delete(groupID);
    }

    function deleteScenario(scenarioID) {
      var scenario = mnStoreService.store("scenarios").get(scenarioID);
      mnStoreService.store("scenarios").deleteItem(scenario);
      scenario.groups.forEach(function (groupID) {
        var group = mnStoreService.store("groups").get(groupID);
        mnStoreService.store("groups").deleteItem(group);
        group.charts.forEach(function (chartID) {
          mnStoreService.store("charts").delete(chartID);
        });
      });
    }

    function copyScenario(scenario, copyFrom) {
      scenario = mnStoreService.store("scenarios").add(scenario);
      scenario.groups = (copyFrom.groups || []).map(function (groupID) {
        var groupToCopy = mnStoreService.store("groups").get(groupID);
        var copiedGroup = mnStoreService.store("groups").add(groupToCopy);
        copiedGroup.preset = false;
        copiedGroup.charts = (copiedGroup.charts || []).map(function (chartID) {
          var chartToCopy = mnStoreService.store("charts").get(chartID);
          var copiedChart = mnStoreService.store("charts").add(chartToCopy);
          copiedChart.preset = false;
          return copiedChart.id;
        });
        return copiedGroup.id;
      });
    }

    function getStatsTitle(stats) {
      return Object.keys(stats).map(function (descPath) {
        var desc = mnStatisticsNewService.readByPath(descPath);
        return desc ? desc.title : descPath.split(".").pop();
      }).join(", ");
    }

    function getStatsDesc(stats) {
      return Object.keys(stats).map(function (descPath) {
        var desc = mnStatisticsNewService.readByPath(descPath);
        if (desc) {
          return "<b>" + desc.title + "</b><p>" + desc.desc + "</p>";
        } else {
          return "<b>" + descPath.split(".").pop() + "</b>" +
            "<p>There is no such stat name anymore. Edit the chart in order to remove it.</p>";
        }
      }).join("");
    }

    function getStatsUnits(stats) {
      var units = {};
      Object.keys(stats).forEach(function (descPath) {
        if (!stats[descPath]) {
          return;
        }
        var desc = mnStatisticsNewService.readByPath(descPath);
        if (desc) {
          units[desc.unit] = true;
        }
      });
      return units;
    }

    function getStatsV2(config, zoom, bucket) {
      var requests = [];
      var data = {
        startTS: 0 - Number(zoom),
        bucket: bucket,
        step: 1
      };
      if (config.specificStat) {
        angular.forEach(config.stats, function (descPath, statName) {
          data.statName = statName;
        });
        requests.push(
          $http({type: "GET",
                 url: "/_uistats/v2",
                 params: Object.assign({}, data)
                }));
      } else {
        angular.forEach(config.stats, function (descPath, statName) {
          requests.push(
            $http({type: "GET",
                   url: "/_uistats/v2",
                   params: Object.assign({statName: statName, host: "aggregate"}, data)
                  }));
        });
      }

      return $q.all(requests);
    }

    function readByPath(descPath) {
      var paths = descPath.split('.');
      var statsDesc = mnStatisticsDescriptionService.stats;
      var i;

      for (i = 0; i < paths.length; ++i) {
        if (statsDesc[paths[i]] == undefined) {
          return undefined;
        } else {
          statsDesc = statsDesc[paths[i]];
        }
      }
      return statsDesc;
    }

    function unsubscribeUIStatsPoller(config, scopeToRemove) {
      var statID = getStatSourcePath(config);
      _.remove(uiStatsScopes[statID], function (scope) {
        return scope === scopeToRemove;
      });

      if (uiStatsScopes[statID] && !uiStatsScopes[statID].length) {
        rootScopes[statID].$destroy();
        delete rootScopes[statID]
        delete pollers[statID];
      }
    }

    function getStatSourcePath(config) {
      var string = config.bucket + config.zoom;

      if (config.specificStat) {
        angular.forEach(config.stats, function (descPath, statName) {
          string += statName;
        });
      } else {
        string += config.node;
      }

      return string;
    }

    function subscribeUIStatsPoller(config, scope) {
      var statID = getStatSourcePath(config);

      rootScopes[statID] = rootScopes[statID] || $rootScope.$new();
      uiStatsScopes[statID] = uiStatsScopes[statID] || [];
      uiStatsScopes[statID].push(scope);
      if (!pollers[statID]) {
        pollers[statID] =
          new mnPoller(rootScopes[statID], function (previousResult) {
            return mnStatisticsNewService
              .doGetStats(config, previousResult)
              .then(null, function (resp) {
                return resp;
              })
          })
          .setInterval(function (response) {
            return response.status === 404 ? 60000 :
              config.interval ? config.interval : response.data.interval;
          })
          .subscribe(function (value) {
            uiStatsScopes[statID].forEach(function (scope) {
              scope["mnUIStats"] = value;
            });
          })
          .reloadOnScopeEvent("reloadUIStatPoller")
          .cycle();
      } else {
        scope["mnUIStats"] = pollers[statID].getLatestResult();
      }

      scope.$on("$destroy", function () {
        mnStatisticsNewService.unsubscribeUIStatsPoller(config, scope);
      });
    }

    function prepareNodesList(params) {
      return mnServersService.getNodes().then(function (nodes) {
        var rv = {};
        rv.nodesNames = _(nodes.active).filter(function (node) {
          return !(node.clusterMembership === 'inactiveFailed') && !(node.status === 'unhealthy');
        }).pluck("hostname").value();

        rv.nodesNames.unshift("All Server Nodes (" + rv.nodesNames.length + ")");
        rv.nodesNames.selected = params.statsHostname === "all" ? rv.nodesNames[0] : params.statsHostname;

        return rv;
      });
    }

    function doGetStats(chartConfig, previousResult) {
      var reqParams = {
        zoom: chartConfig.zoom,
        bucket: chartConfig.bucket
      };
      if (chartConfig.specificStat) {
        var descPath = Object.keys(chartConfig.stats)[0];
        var splitted = descPath.split(".");
        var service = splitted[0].substring(1, splitted[0].length-1);
        var maybeItem = descPath.includes("@items") && (chartConfig.items || {})[service];
        reqParams.statName = (maybeItem || "") + splitted[splitted.length - 1];
      } else {
        if (chartConfig.node !== "all") {
          reqParams.node = chartConfig.node;
        }
      }
      if (previousResult && !previousResult.status) {
        reqParams.haveTStamp = previousResult.stats.lastTStamp;
      }
      return $http({
        url: '/_uistats',
        method: 'GET',
        params: reqParams
      }).then(function (resp) {
        // if (previousResult && !previousResult.status) {
        //   resp.data = maybeApplyDelta(previousResult, resp.data);
        // }
        // stats.serverDate = mnParseHttpDateFilter(data[0].headers('date')).valueOf();
        // stats.clientDate = (new Date()).valueOf();
        var samples = {};
        angular.forEach(resp.data.stats, function (subSamples, subName) {
          var timestamps = subSamples.timestamp;
          for (var k in subSamples) {
            if (k == "timestamp") {
              continue;
            }
            samples[k] = subSamples[k];
            samples[k].timestamps = timestamps;
          }
        });
        resp.data.samples = samples;
        return resp;
      });
    }

    function maybeApplyDelta(prevValue, value) {
      var stats = value.stats;
      var prevStats = prevValue.stats || {};
      for (var kind in stats) {
        var newSamples = restoreOpsBlock(prevStats[kind],
                                         stats[kind],
                                         value.samplesCount + 1);
        stats[kind] = newSamples;
      }
      return value;
    }

    function restoreOpsBlock(prevSamples, samples, keepCount) {
      var prevTS = prevSamples.timestamp;
      if (samples.timestamp && samples.timestamp.length == 0) {
        // server was unable to return any data for this "kind" of
        // stats
        if (prevSamples && prevSamples.timestamp && prevSamples.timestamp.length > 0) {
          return prevSamples;
        }
        return samples;
      }
      if (prevTS == undefined ||
          prevTS.length == 0 ||
          prevTS[prevTS.length-1] != samples.timestamp[0]) {
        return samples;
      }
      var newSamples = {};
      for (var keyName in samples) {
        var ps = prevSamples[keyName];
        if (!ps) {
          ps = [];
          ps.length = keepCount;
        }
        newSamples[keyName] = ps.concat(samples[keyName].slice(1)).slice(-keepCount);
      }
      return newSamples;
    }

    function doAddPresetScenario() {
      presetScenario().forEach(function (scenario) {
        scenario.preset = true;
        scenario.groups = scenario.groups.map(function (group) {
          group.preset = true;
          group.charts = group.charts.map(function (chart) {
            chart.preset = true;
            chart = mnStoreService.store("charts").add(chart);
            return chart.id;
          });
          group = mnStoreService.store("groups").add(group);
          return group.id;
        });
        mnStoreService.store("scenarios").add(scenario);
      });
    }

    function presetScenario() {
      return [{
        name: "Cluster Overview",
        desc: "Stats showing the general health of your cluster.",
        groups: [{
          name: "Server Resources",
          charts: [{
            stats: {"@system.cpu_utilization_rate": true},
            size: "small",
            specificStat: true // for single-stat chart
          }, {
            stats: {"@system.mem_actual_free": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@system.swap_used": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@kv-.ops": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@kv-.ops": true,
                    "@kv-.ep_cache_miss_rate": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.cmd_get": true,
                    "@kv-.cmd_set": true,
                    "@kv-.delete_hits": true},
            size: "medium",
            specificStat: false
          }]
      }] }, {  // 2nd scenario starts here with the comma ///////////////////////

        name: "General Troubleshooting",
        desc: "Most common stats - per service.",
        groups: [{
          name: "Server Resources",
          charts: [{
            stats: {"@system.cpu_utilization_rate": true},
            size: "small",
            specificStat: true // for single-stat chart
          }, {
            stats: {"@system.mem_actual_free": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@system.swap_used": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@system.rest_requests": true},
            size: "small",
            specificStat: true
          }]
          }, {
          name: "Data Service",
          charts: [{
            stats: {"@kv-.mem_used": true,
                    "@kv-.ep_mem_low_wat": true,
                    "@kv-.ep_mem_high_wat": true},
            size: "medium",
            specificStat: false // false for multi-stat chart
          }, {
            stats: {"@kv-.ep_kv_size": true,
                    "@kv-.ep_meta_data_memory": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ops": true,
                    "@kv-.ep_cache_miss_rate": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.cmd_get": true,
                    "@kv-.cmd_set": true,
                    "@kv-.delete_hits": true},
            size: "medium",
            specificStat: false
          }]
      }, {
          name: "Index Service",
          charts: [{
            stats: {"@index.index_ram_percent": true,
                    "@index.index_remaining_ram": true},
            size: "small",
            specificStat: false
          }, {
            stats: {"@index-.index/data_size": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@index-.index/disk_size": true},
            size: "small",
            specificStat: true
          }]
        }, {
          name: "Query Service",
          charts: [{
            stats: {"@query.query_requests_1000ms": true,
                    "@query.query_requests_500ms": true,
                    "@query.query_requests_5000ms": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@query.query_selects": true,
                    "@query.query_requests": true},
            size: "medium",
            specificStat: false
          }]
        }, {
          name: "Analytics Service",
          charts: [{
            stats: {"@cbas-.cbas/incoming_records_count": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@cbas.cbas_heap_used": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@cbas.cbas_disk_used": true},
            size: "small",
            specificStat: true
          }, {
            stats: {"@cbas.cbas_system_load_average": true},
            size: "small",
            specificStat: true
          }]
        }, {
          name: "vBucket Resources",
          charts: [{
            stats: {"@kv-.vb_active_num": true,
                    "@kv-.vb_replica_num": true,
                    "@kv-.vb_pending_num": true,
                    "@kv-.ep_vb_total": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.curr_items": true,
                    "@kv-.vb_replica_curr_items": true,
                    "@kv-.vb_pending_curr_items": true,
                    "@kv-.curr_items_tot": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.vb_active_resident_items_ratio": true,
                    "@kv-.vb_replica_resident_items_ratio": true,
                    "@kv-.vb_pending_resident_items_ratio": true,
                    "@kv-.ep_resident_items_rate": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.vb_active_ops_create": true,
                    "@kv-.vb_avg_replica_ops_create": true,
                    "@kv-.vb_avg_pending_ops_create": true,
                    "@kv-.ep_ops_create": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.vn_active_eject": true,
                    "@kv-.vb_replica_eject": true,
                    "@kv-.vb_pending_eject": true,
                    "@kv-.ep_num_value_ejects": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.vb_active_itm_memory": true,
                    "@kv-.vb_replica_itm_memory": true,
                    "@kv-.vb_pending_itm_memory": true,
                    "@kv-.ep_kv_size": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.vb_active_meta_data_memory": true,
                    "@kv-.vb_avg_replica_meta_data_memory": true,
                    "@kv-.vb_avg_pending_meta_data_memory": true,
                    "@kv-.ep_meta_data_memory": true},
            size: "medium",
            specificStat: false
          }]
          }, {
            name: "DCP Queues",
            charts: [{
            stats: {"@kv-.ep_dcp_views+indexes_count": true,
                    "@kv-.ep_dcp_cbas_count": true,
                    "@kv-.ep_dcp_replica_count": true,
                    "@kv-.ep_dcp_xdcr_count": true,
                    "@kv-.ep_dcp_other_count": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_producer_count": true,
                    "@kv-.ep_dcp_cbas_producer_count": true,
                    "@kv-.ep_dcp_replica_producer_count": true,
                    "@kv-.ep_dcp_xdcr_producer_count": true,
                    "@kv-.ep_dcp_other_producer_count": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_items_remaining": true,
                    "@kv-.ep_dcp_cbas_items_remaining": true,
                    "@kv-.ep_dcp_replica_items_remaining": true,
                    "@kv-.ep_dcp_xdcr_items_remaining": true,
                    "@kv-.ep_dcp_other_items_remaining": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_items_sent": true,
                    "@kv-.ep_dcp_cbas_items_sent": true,
                    "@kv-.ep_dcp_replica_items_sent": true,
                    "@kv-.ep_dcp_xdcr_items_sent": true,
                    "@kv-.ep_dcp_other_items_sent": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_total_bytes": true,
                    "@kv-.ep_dcp_cbas_total_bytes": true,
                    "@kv-.ep_dcp_replica_total_bytes": true,
                    "@kv-.ep_dcp_xdcr_total_bytes": true,
                    "@kv-.ep_dcp_other_total_bytes": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_backoff": true,
                    "@kv-.ep_dcp_cbas_backoff": true,
                    "@kv-.ep_dcp_replica_backoff": true,
                    "@kv-.ep_dcp_xdcr_backoff": true,
                    "@kv-.ep_dcp_other_backoff": true},
            size: "medium",
            specificStat: false
          }
        ]
        }, {
          name: "Disk Queues",
          charts: [{
            stats: {"@kv-.ep_dcp_views+indexes_count": true,
                    "@kv-.ep_dcp_cbas_count": true,
                    "@kv-.ep_dcp_replica_count": true,
                    "@kv-.ep_dcp_xdcr_count": true,
                    "@kv-.ep_dcp_other_count": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_producer_count": true,
                    "@kv-.ep_dcp_cbas_producer_count": true,
                    "@kv-.ep_dcp_replica_producer_count": true,
                    "@kv-.ep_dcp_xdcr_producer_count": true,
                    "@kv-.ep_dcp_other_producer_count": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_items_remaining": true,
                    "@kv-.ep_dcp_cbas_items_remaining": true,
                    "@kv-.ep_dcp_replica_items_remaining": true,
                    "@kv-.ep_dcp_xdcr_items_remaining": true,
                    "@kv-.ep_dcp_other_items_remaining": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_items_sent": true,
                    "@kv-.ep_dcp_cbas_items_sent": true,
                    "@kv-.ep_dcp_replica_items_sent": true,
                    "@kv-.ep_dcp_xdcr_items_sent": true,
                    "@kv-.ep_dcp_other_items_sent": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_total_bytes": true,
                    "@kv-.ep_dcp_cbas_total_bytes": true,
                    "@kv-.ep_dcp_replica_total_bytes": true,
                    "@kv-.ep_dcp_xdcr_total_bytes": true,
                    "@kv-.ep_dcp_other_total_bytes": true},
            size: "medium",
            specificStat: false
          }, {
            stats: {"@kv-.ep_dcp_views+indexes_backoff": true,
                    "@kv-.ep_dcp_cbas_backoff": true,
                    "@kv-.ep_dcp_replica_backoff": true,
                    "@kv-.ep_dcp_xdcr_backoff": true,
                    "@kv-.ep_dcp_other_backoff": true},
            size: "medium",
            specificStat: false
          }
        ]
        }
      ]
      }]
    }
  }
})();
