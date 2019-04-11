(function () {
  "use strict";

  angular
    .module('mnStatisticsNewService', ["mnServersService", "mnUserRolesService", 'mnPoll', "mnStatisticsDescriptionService", "mnHelper"])
    .factory('mnStatisticsNewService', mnStatisticsNewServiceFactory);

  function mnStatisticsNewServiceFactory($http, $q, mnServersService, mnPoller, $rootScope, mnStatisticsDescriptionService, mnUserRolesService, mnHelper) {
    var mnStatisticsNewService = {
      prepareNodesList: prepareNodesList,
      export: {
        scenarios: []
      },
      doGetStats: doGetStats,
      getStatSourcePath: getStatSourcePath,
      subscribeToChartStats: subscribeToChartStats,
      unsubscribeChartStats: unsubscribeChartStats,
      addUpdateScenario: addUpdateScenario,
      addUpdateGroup: addUpdateGroup,
      addUpdateChart: addUpdateChart,
      deleteScenario: deleteScenario,
      deleteGroup: deleteGroup,
      saveScenarios: saveScenarios,
      readByPath: readByPath,
      presetScenario: presetScenario,
      getStatsV2: getStatsV2,
      getStatsUnits: getStatsUnits,
      getStatsTitle: getStatsTitle,
      tickMultiFormat: d3.time.format.multi([
        ["%-I:%M%p", function (d) {return d.getMinutes(); }], // not the beginning of the hour
        ["%-I%p", function (d) { return d.getHours(); }], // not midnight
        ["%b %-d", function (d) { return d.getDate() != 1; }], // not the first of the month
        ["%b %-d", function (d) { return d.getMonth(); }], // not Jan 1st
        ["%Y", function () { return true; }]
      ])
    };

    var pollers = {};
    var chartScopes = {};
    var rootScopes = {};

    return mnStatisticsNewService;

    function presetScenario() {
      return saveScenarios([{
        name: "Cluster Overview",
        desc: "Stats showing the general health of your cluster.",
        preset: true,
        id: mnHelper.generateID(),
        groups: [(function (groupId) {
          return {
            id: groupId,
            name: "Server Resources",
            preset: true,
            charts: [{
              stats: {"cpu_utilization_rate": "@system"},
              preset: true,
              size: "small",
              specificStat: true, // for single-stat chart
              group: groupId,
              id: mnHelper.generateID(),
            }, {
              stats: {"mem_actual_free": "@system"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID(),
            }, {
              stats: {"swap_used": "@system"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID(),
            }, {
              stats: {"rest_requests": "@system"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID(),
            }]
          }
        })(mnHelper.generateID()), // 2nd group starts here with the comma ////
        (function (groupId) {
          return {
            id: groupId,
            name: "Data Service Overview (per bucket)",
            preset: true,
            charts: [{
              stats: {"ops": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"mem_used": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"couch_docs_actual_disk_size": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"ep_resident_items_rate": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID())]
      }, // 2nd scenario starts here with the comma ///////////////////////////
      {
        name: "Data Service",
        desc: "Data Service stats per bucket.",
        preset: true,
        id: mnHelper.generateID(),
        groups: [(function (groupId) {
          return {
            id: groupId,
            name: "Memory",
            preset: true,
            charts: [{
              stats: {"mem_used": "@kv-", "ep_mem_low_wat": "@kv-", "ep_mem_high_wat": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false, // false for multi-stat chart
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"ep_kv_size": "@kv-", "ep_meta_data_memory": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID()),
        (function (groupId) {
          return {
            id: groupId,
            name: "Ops",
            preset: true,
            charts: [{
              stats: {"ops": "@kv-","ep_cache_miss_rate": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"cmd_get": "@kv-", "cmd_set": "@kv-", "delete_hits": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID()),
        (function (groupId) {
          return {
            id: groupId,
            name: "Disk",
            preset: true,
            charts: [{
              stats: {"couch_docs_actual_disk_size": "@kv-", "couch_docs_data_size": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"disk_write_queue": "@kv-", "ep_data_read_failed": "@kv-", "ep_data_write_failed": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID()),
        (function (groupId) {
          return {
            id: groupId,
            name: "vBuckets",
            preset: true,
            charts: [{
              stats: {"ep_vb_total": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"vb_active_num": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"vb_pending_num": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"vb_replica_num": "@kv-"},
              preset: true,
              size: "small",
              specificStat: true,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID()),
        (function (groupId) {
          return {
            id: groupId,
            name: "DCP Queues",
            preset: true,
            charts: [{
              stats: {"ep_dcp_views+indexes_count": "@kv-", "ep_dcp_cbas_count": "@kv-", "ep_dcp_replica_count": "@kv-", "ep_dcp_xdcr_count": "@kv-", "ep_dcp_other_count": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"ep_dcp_views+indexes_producer_count": "@kv-", "ep_dcp_cbas_producer_count": "@kv-", "ep_dcp_replica_producer_count": "@kv-", "ep_dcp_xdcr_producer_count": "@kv-", "ep_dcp_other_producer_count": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }, {
              stats: {"ep_dcp_views+indexes_items_remaining": "@kv-", "ep_dcp_cbas_items_remaining": "@kv-", "ep_dcp_replica_items_remaining": "@kv-", "ep_dcp_xdcr_items_remaining": "@kv-", "ep_dcp_other_items_remaining": "@kv-"},
              preset: true,
              size: "medium",
              specificStat: false,
              group: groupId,
              id: mnHelper.generateID()
            }]
          }
        })(mnHelper.generateID())]
      }]);
    }

    function getStatsTitle(stats) {
      return _.map(stats, function (descPath, name) {
        var desc = mnStatisticsNewService.readByPath(descPath, name);
        return desc.title;
      }).join(", ");
    }

    function getStatsUnits(stats) {
      var units = {};
      angular.forEach(stats, function (descPath, name) {
        if (!descPath) {
          return;
        }
        var desc = mnStatisticsNewService.readByPath(descPath, name);
        units[desc.unit] = true;
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

    function readByPath(path, name) {
      var paths = path.split('.');
      var maybeItIsItemName = name.split("/");
      name = maybeItIsItemName[maybeItIsItemName.length - 1];
      paths.push(name);
      var current = mnStatisticsDescriptionService.stats;
      var i;

      for (i = 0; i < paths.length; ++i) {
        if (current[paths[i]] == undefined) {
          return undefined;
        } else {
          current = current[paths[i]];
        }
      }
      return current;
    }

    function unsubscribeChartStats(config, scopeToRemove, bucket) {
      var statID = getStatSourcePath(config, bucket);
      _.remove(chartScopes[statID], function (scope) {
        return scope === scopeToRemove;
      });

      if (chartScopes[statID] && !chartScopes[statID].length) {
        rootScopes[statID].$destroy();
        delete rootScopes[statID]
        delete pollers[statID];
      }
    }

    function addUpdateChart(newChart, group) {
      var charts = group.charts;

      var statName;
      if (newChart.specificStat) {
        _.forEach(newChart.stats, function (value, key) {
          statName = key;
        });
      }

      if (newChart.id) {
        var index = _.findIndex(charts, {'id': newChart.id});
        charts[index] = newChart;
      } else {
        var chartId = mnHelper.generateID();
        charts = charts || [];
        newChart.id = chartId;
        charts.push(newChart);
      }

      return saveScenarios();
    }

    function saveScenarios(scenarios) {
      return mnUserRolesService.getUserProfile().then(function (profile) {
        profile.scenarios = scenarios || mnStatisticsNewService.export.scenarios;
        return mnUserRolesService.putUserProfile(profile);
      });
    }

    function addUpdateGroup(newGroup) {
      newGroup.id = mnHelper.generateID();
      mnStatisticsNewService.export.scenarios.selected.groups.push(newGroup);
      return saveScenarios();
    }

    function deleteGroup(group) {
      var groups = mnStatisticsNewService.export.scenarios.selected.groups;
      var index = _.findIndex(groups, {'id': group.id});
      groups.splice(index, 1);
      return saveScenarios();
    }


    function deleteScenario(scenario) {
      var scenarios = mnStatisticsNewService.export.scenarios;
      var index = _.findIndex(scenarios, {'id': scenario.id});
      scenarios.splice(index, 1);
      return saveScenarios();
    }

    function addUpdateScenario(newSenario) {
      var scenarios = mnStatisticsNewService.export.scenarios;

      if (newSenario.id) {
        var index = _.findIndex(scenarios, {'id': newSenario.id});
        scenarios[index].name = newSenario.name;
        scenarios[index].desc = newSenario.desc;
      } else {
        newSenario.id = mnHelper.generateID();
        scenarios.push(newSenario);
      }

      return saveScenarios();
    }

    function getStatSourcePath(chart, bucket) {
      var string = bucket;

      if (chart.specificStat) {
        angular.forEach(chart.stats, function (descPath, statName) {
          string += statName;
        });
      } else {
        string += chart.node;
      }

      return string;
    }

    function subscribeToChartStats(config, chartScope, bucket, zoom) {
      var config1 = _.clone(config, true);
      var statID = getStatSourcePath(config1, bucket);
      config1.bucket = config1.bucket || bucket;
      config1.zoom = config1.zoom || zoom;

      rootScopes[statID] = rootScopes[statID] || $rootScope.$new();
      chartScopes[statID] = chartScopes[statID] || [];
      chartScopes[statID].push(chartScope);
      if (!pollers[statID]) {
        pollers[statID] =
          new mnPoller(rootScopes[statID], function (previousResult) {
            return mnStatisticsNewService.doGetStats(config1, previousResult);
          })
          .setInterval(function (response) {
            return response.data.interval;
          })
          .subscribe(function (value) {
            chartScopes[statID].forEach(function (scope) {
              scope["mnChartStats"] = value;
            });
          })
          .reloadOnScopeEvent("reloadChartPoller")
          .cycle();
      } else {
        !config.preset && pollers[statID].reload();
      }
    }

    function prepareNodesList(params) {
      return mnServersService.getNodes().then(function (nodes) {
        var rv = {};
        rv.nodesNames = _(nodes.active).filter(function (node) {
          return !(node.clusterMembership === 'inactiveFailed') && !(node.status === 'unhealthy');
        }).pluck("hostname").value();

        rv.nodesNames.selected = params.statsHostname || rv.nodesNames[0];
        return rv;
      });
    }

    function doGetStats(chartConfig, previousResult) {
      var reqParams = {
        zoom: chartConfig.zoom,
          // || mnStatisticsNewService.export.scenarios.selected.zoom,
        bucket: chartConfig.bucket
      };
      if (chartConfig.specificStat) {
        angular.forEach(chartConfig.stats, function (descPath, statName) {
          reqParams.statName = statName;
        });
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

  }
})();
