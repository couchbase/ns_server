import angular from "/ui/web_modules/angular.js";
import _ from "/ui/web_modules/lodash.js";
import {timeFormat} from "/ui/web_modules/d3-time-format.js";
import {timeMinute,
        timeHour,
        timeDay,
        timeMonth,
        timeYear} from "/ui/web_modules/d3-time.js";
import {min as d3Min, max as d3Max} from "/ui/web_modules/d3-array.js"

import mnPoll from "/ui/app/components/mn_poll.js";
import mnStoreService from "/ui/app/components/mn_store_service.js";
import mnPoolDefault from "/ui/app/components/mn_pool_default.js";

import mnServersService from "./mn_servers_service.js"
import mnStatisticsDescriptionService from "./mn_statistics_description_service.js";
import mnStatisticsDescription from "./mn_statistics_description.js";

export default "mnStatisticsNewService";

angular
  .module('mnStatisticsNewService', [
    mnServersService,
    mnPoll,
    mnStatisticsDescriptionService,
    mnStoreService,
    mnPoolDefault
  ])
  .factory('mnStatisticsNewService', mnStatisticsNewServiceFactory);

function mnStatisticsNewServiceFactory($http, mnServersService, mnPoller, $rootScope, mnStatisticsDescriptionService, mnStoreService, mnPoolDefault) {
  var rootScope = $rootScope.$new();
  var perChartConfig = [];
  var perChartStatsPath = [];
  var perChartScopes = [];
  var currentPerChartScopes = [];
  var formatSecond = timeFormat("%-I:%M:%S%p");
  var formatMinute = timeFormat("%-I:%M%p");
  var formatHour = timeFormat("%-I%p");
  var formatDayMonth = timeFormat("%b %-d");
  var formatYear = timeFormat("%Y");

  var mnStatisticsNewService = {
    prepareNodesList: prepareNodesList,
    export: {
      scenario: {}
    },
    subscribeUIStatsPoller: subscribeUIStatsPoller,
    descriptionPathsToStatNames: descriptionPathsToStatNames,
    descriptionPathToStatName: descriptionPathToStatName,
    defaultZoomInterval: defaultZoomInterval,

    copyScenario: copyScenario,
    deleteScenario: deleteScenario,
    deleteGroup: deleteGroup,
    deleteChart: deleteChart,
    doAddPresetScenario: doAddPresetScenario,

    getStatsDirectory: getStatsDirectory,
    get70StatUniqueName: get70StatUniqueName,
    readByPath: readByPath,
    getStatsUnits: getStatsUnits,
    getStatsTitle: getStatsTitle,
    getStatsDesc: getStatsDesc,
    buildChartConfig: buildChartConfig,
    tickMultiFormat: multiFormat,
    heartbeat: new mnPoller(rootScope, function () {
      currentPerChartScopes = [...perChartScopes];
      return mnPoolDefault.export.compat.atLeast70 ?
        postStatsRange([...perChartConfig]) :
        postStats([...perChartConfig]);
    })
      .setInterval(function (resp) {
        return resp.interval || 1000;
      })
      .subscribe(function (value) {
        if (!value.data) {
          return;
        }
        if (mnPoolDefault.export.compat.atLeast70) {
          currentPerChartScopes.forEach(scope => delete scope["mnUIStats"]);
          currentPerChartScopes.forEach(unpack70Stats(value));
        } else {
          currentPerChartScopes.forEach(function (scope, i) {
            scope["mnUIStats"] = value.data[i];
          });
        }
      })
  };

  return mnStatisticsNewService;

  function buildChartConfig(stats, statName, currentNode, title, unit, axis) {
    currentNode = currentNode == "all" ? "aggregate" : currentNode;
    var perNodeStats = stats.stats[statName] && stats.stats[statName][currentNode];
    var onlyValues = [];
    var values = [];

    if (perNodeStats) {
      if (mnPoolDefault.export.compat.atLeast70) {
        perNodeStats.values.forEach(([ts, v]) => {
          var convertValue = Number(v);
          onlyValues.push(convertValue);
          values.push([ts * 1000, convertValue]);
        });
      } else {
        stats.timestamps.forEach((ts, i) => {
          var v = perNodeStats[i];
          var convertValue = v === null ? undefined : v;
          onlyValues.push(convertValue);
          values.push([ts, convertValue]);
        });
      }
    }

    return {
      type: 'line',
      unit: unit,
      max: d3Max(onlyValues) || 1,
      min: d3Min(onlyValues) || 0,
      yAxis: axis,
      key: title,
      values: values
    };
  }

  function defaultZoomInterval(zoom) {
    return function (resp) {
      return resp.interval || (function () {
        switch (zoom) {
        case "minute": return 1000;
        default: return 15000;
        }
      })();
    };
  }

  // Define filter conditions
  function multiFormat(date) {
    return (timeMinute(date) < date ? formatSecond
            : timeHour(date) < date ? formatMinute
            : timeDay(date) < date ? formatHour
            : timeMonth(date) < date ? formatDayMonth
            : timeYear(date) < date ? formatDayMonth
            : formatYear)(date);
  }

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
      url: "/pools/default/buckets/" + bucket + "/statsDirectory",
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

  function readByPath(descPath) {
    var paths = descPath.split('.');
    var statsDesc = mnStatisticsDescriptionService.getStats();
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

  function isPerBucketStat(path) {
    return path.split(".")[0].includes("-");
  }

  function postStats(perChartConfig) {
    return $http({
      url: '/_uistats',
      method: 'POST',
      mnHttp: {
        group: "global",
        isNotForm: true
      },
      data: perChartConfig
    });
  }

  function postStatsRange(perChartConfig) {
    return $http({
      url: '/pools/default/stats/range/',
      method: 'POST',
      mnHttp: {
        group: "global",
        isNotForm: true
      },
      data: perChartConfig
    });
  }

  function getServiceNameFromDescriptionPath(descPath) {
    var splitted = descPath.split(".");
    return splitted[0].substring(1, splitted[0].length-1);
  }

  function descriptionPathToStatName(descPath, items) {
    if (mnPoolDefault.export.compat.atLeast70) {
      return descPath;
    } else {
      let splitted = descPath.split(".");
      let service = getServiceNameFromDescriptionPath(descPath);
      let maybeItem = descPath.includes("@items") && ((items || {})[service])
      return (maybeItem || "") + splitted[splitted.length - 1];
    }
  }

  function getStatsProp(stats) {
    return Array.isArray(stats) ? stats : Object.keys(stats);
  }

  function descriptionPathsToStatNames(stats, items) {
    return getStatsProp(stats).map(function (descPath) {
      return descriptionPathToStatName(descPath, items);
    });
  }


  function zoomToMS(zoom) {
    switch (zoom) {
    case "minute": return 60000;
    case "hour": return 3600000;
    case "day": return 86400000;
    case "week": return 604800000
    case "month": return 2628000000;
    default: return zoom
    }
  }

  function zoomToStep(zoom) {
    return zoomToMS(zoom) / 60000;
  }

  function get70StatUniqueName(cfg) {
    return cfg.metric.name + (cfg.applyFunctions ? ("_" + cfg.applyFunctions.join("")) : "");
  }

  function unpack70Stats(resp) {
    return function (scope, i) {
      if (!resp.data[i]) {
        return;
      }
      var config = perChartConfig[i];
      if (!config) {
        return;
      }
      var statPath = perChartStatsPath[i];
      var data = resp.data[i].data[0];
      scope["mnUIStats"] = scope["mnUIStats"] || {stats:{}};
      var maybeScopeHasStat = scope["mnUIStats"].stats[statPath] || {};
      if (!config.aggregationFunction) {
        scope["mnUIStats"].stats[statPath] =
          resp.data[i].data.reduce((acc, data) => {
            acc[data.metric.nodes[0]] = data;
            return acc;
          }, maybeScopeHasStat);
      } else {
        scope["mnUIStats"].stats[statPath] =
          maybeScopeHasStat;
        maybeScopeHasStat[config.aggregationFunction ? "aggregate" : data.nodes[0]] = data;
      }
    }
  }

  function packStatsConfig(config) {
    let cfg = {};
    let start = 0 - zoomToMS(config.zoom);
    cfg.step = config.step || zoomToStep(config.zoom);

    if (config.node !== "all") {
      cfg.nodes = [config.node];
    }

    if (mnPoolDefault.export.compat.atLeast70) {
      cfg.start = start / 1000;
      let rv = [];
      getStatsProp(config.stats).forEach(statPath => {
        let statDesc = readByPath(statPath);
        if (!statDesc) {
          return;
        }
        let cfg1 = Object.assign({statPath: statPath}, cfg);
        let service = getServiceNameFromDescriptionPath(statPath);
        cfg1.metric = Object.assign({}, statDesc.metric);
        if (isPerBucketStat(statPath)) {
          if (statDesc.bucket === null) {
            delete cfg1.metric.bucket;
          } else {
            cfg1.metric.bucket = config.bucket;
          }
        }
        if (config.node == "all" && !config.specificStat) {
          cfg1.aggregationFunction = statDesc.aggregationFunction;
        }
        if (config.applyFunctions || statDesc.applyFunctions) {
          cfg1.applyFunctions = config.applyFunctions || statDesc.applyFunctions;
        }
        if (statPath.includes("@items")) {
          cfg1.metric[service] = config.items[service];
        }
        let httpParamsModifier = mnStatisticsDescription.maybeGetLabelsModifier(service);
        if (httpParamsModifier) {
          cfg1 = httpParamsModifier(cfg1);
        }
        rv.push(cfg1);
      });
      return rv;
    } else {
      cfg.startTS = start;
      cfg.stats = descriptionPathsToStatNames(config.stats, config.items);
      cfg.bucket = config.bucket;
      if (config.node == "all" && !config.specificStat) {
        cfg.aggregate = true;
      }
      return [cfg];
    }
  }

  function subscribeUIStatsPoller(config, scope) {
    let config1 = packStatsConfig(config);

    function register(config2, statPath) {
      if (mnPoolDefault.export.compat.atLeast70) {
        perChartStatsPath.push(statPath);
        delete config2.statPath;
      }

      perChartConfig.push(config2);
      perChartScopes.push(scope);

      mnStatisticsNewService.heartbeat.throttledReload();
    }

    function omit(config2) {
      var index = perChartConfig.indexOf(config2);
      perChartConfig.splice(index, 1);
      perChartScopes.splice(perChartScopes.indexOf(scope), 1);
      if (mnPoolDefault.export.compat.atLeast70) {
        perChartStatsPath.splice(index, 1);
      }

      if (!perChartConfig.length) {
        mnStatisticsNewService.heartbeat.stop();
      }
    }

    function doOmit(config2) {
      return function () {
        omit(config2);
      };
    }

    function doRegister(config2, statPath) {
      return function () {
        register(config2, statPath);
      };
    }

    config1.forEach((config2) => {
      let statPath = config2.statPath;
      register(config2, statPath);
      let offPause = scope.$on("mnPauseStats", doOmit(config2));
      let offResume = scope.$on("mnResumeStats", doRegister(config2, statPath));
      scope.$on("$destroy", function () {
        offResume && offResume();
        offPause && offPause();
        doOmit(config2)();
      });
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
        name: "Cluster Overview",
        isOpen: true,
        charts: [{
          stats: {"@kv-.ops": true,
                  "@query.query_requests": true,
                  "@fts-.@items.total_queries": true,
                  "@kv-.ep_tmp_oom_errors": true,
                  "@kv-.ep_cache_miss_rate": true,
                  "@kv-.cmd_get": true,
                  "@kv-.cmd_set": true,
                  "@kv-.delete_hits": true,
                  "@kv-.@items.accesses": true
                 },
          size: "large",
          specificStat: false
        }, {
          stats: {"@kv-.mem_used": true,
                  "@kv-.ep_mem_low_wat": true,
                  "@kv-.ep_mem_high_wat": true},
          size: "medium",
          specificStat: false // false for multi-stat chart
        }, {
          stats: {"@kv-.curr_items": true,
                  "@kv-.vb_replica_curr_items": true,
                  "@kv-.vb_active_resident_items_ratio": true,
                  "@kv-.vb_replica_resident_items_ratio": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.disk_write_queue": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@kv-.ep_dcp_replica_items_remaining": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@kv-.ep_data_read_failed": true,
                  "@kv-.ep_data_write_failed": true,
                  "@query.query_errors": true,
                  "@query.total_queries_error": true,
                  "@eventing.eventing/failed_count": true},
          size: "small",
          specificStat: false
        }, {
          stats: {"@query.query_requests_250ms": true,
                  "@query.query_requests_500ms": true,
                  "@query.query_requests_1000ms": true,
                  "@query.query_requests_5000ms": true},
          size: "small",
          specificStat: false
        }, {
          stats: {"@xdcr-.replication_changes_left": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@index-.@items.num_docs_pending+queued": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@fts-.@items.num_mutations_to_index": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@eventing.eventing/dcp_backlog": true},
          size: "small",
          specificStat: true
        },
                ]
      },
               {
                 name: "Node Resources",
                 isOpen: false,
                 charts: [{
                   stats: {"@system.cpu_utilization_rate": true},
                   size: "medium",
                   specificStat: true // for single-stat chart
                 }, {
                   stats: {"@system.rest_requests": true},
                   size: "medium",
                   specificStat: true
                 }, {
                   stats: {"@system.mem_actual_free": true},
                   size: "medium",
                   specificStat: false
                 }, {
                   stats: {"@system.swap_used": true},
                   size: "medium",
                   specificStat: true
                 }]
               }
              ]
    },{  // 2nd scenario starts here with the comma ///////////////////////

      name: "All Services",
      desc: 'Most common stats, arranged per service. Customize and make your own dashboard with "new dashboard... " below.',
      groups: [{
        name: "Data (Docs/Views/XDCR)",
        isOpen: true,
        charts: [{
          stats: {"@kv-.mem_used": true,
                  "@kv-.ep_mem_low_wat": true,
                  "@kv-.ep_mem_high_wat": true,
                  "@kv-.ep_kv_size": true,
                  "@kv-.ep_meta_data_memory": true,
                  "@kv-.vb_active_resident_items_ratio": true},
          size: "medium",
          specificStat: false // false for multi-stat chart
        }, {
          stats: {"@kv-.ops": true,
                  "@kv-.ep_cache_miss_rate": true,
                  "@kv-.cmd_get": true,
                  "@kv-.cmd_set": true,
                  "@kv-.delete_hits": true,
                  "@kv-.@items.accesses": true,
                  "@kv-.ep_num_ops_set_meta": true
                 },
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.ep_dcp_views+indexes_items_remaining": true,
                  "@kv-.ep_dcp_cbas_items_remaining": true,
                  "@kv-.ep_dcp_replica_items_remaining": true,
                  "@kv-.ep_dcp_xdcr_items_remaining": true,
                  "@kv-.ep_dcp_eventing_items_remaining": true,
                  "@kv-.ep_dcp_other_items_remaining": true,
                  "@xdcr-.replication_changes_left": true
                 },
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.ep_bg_fetched": true,
                  "@kv-.ep_data_read_failed": true,
                  "@kv-.ep_data_write_failed": true,
                  "@kv-.ep_ops_create": true,
                  "@kv-.ep_ops_update": true
                 },
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.ep_diskqueue_items": true},
          size: "small",
          specificStat: true
        }]
      }, {
        name: "Query",
        isOpen: false,
        charts: [{
          stats: {"@query.query_requests_1000ms": true,
                  "@query.query_requests_500ms": true,
                  "@query.query_requests_5000ms": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@query.query_selects": true,
                  "@query.query_requests": true,
                  "@query.query_warnings": true,
                  "@query.query_invalid_requests": true,
                  "@query.query_errors": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@query.query_avg_req_time": true,
                  "@query.query_avg_svc_time": true},
          size: "small",
          specificStat: false
        }, {
          stats: {"@query.query_avg_result_count": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@query.query_avg_response_size": true},
          size: "small",
          specificStat: false
        }]
      }, {
        name: "Index",
        isOpen: false,
        charts: [{
          stats: {"@index-.index/num_rows_returned": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@index-.@items.num_docs_pending+queued": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@index-.index/data_size": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@index-.index/disk_size": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@index.index_ram_percent": true,
                  "@index.index_remaining_ram": true,
                  "@index-.index/data_size": true,
                  "@index-.index/disk_size": true},
          size: "medium",
          specificStat: false
        }]
      }, {
        name: "Search",
        isOpen: false,
        charts: [{
          stats: {"@fts-.fts/num_bytes_used_disk": true,
                  "@fts.fts_num_bytes_used_ram": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@fts-.@items.total_queries": true,
                  "@fts-.@items.total_queries_error": true,
                  "@fts-.@items.total_queries_slow": true,
                  "@fts-.@items.total_queries_timeout": true,
                  "@fts.fts_total_queries_rejected_by_herder": true},
          size: "medium",
          specificStat: false
        }]
      }, {
        name: "Analytics",
        enterprise: true,
        isOpen: false,
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
        name: "Eventing",
        enterprise: true,
        isOpen: false,
        charts: [{
          stats: {"@eventing.eventing/dcp_backlog": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@eventing.eventing/failed_count": true,
                  "@eventing.eventing/timeout_count": true},
          size: "small",
          specificStat: false
        }]
      },  {
        name: "XDCR",
        isOpen: false,
        charts: [{
          stats: {"@xdcr-.replication_changes_left": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@xdcr-.@items.changes_left": true},
          size: "small",
          specificStat: true
        }, {
          stats: {"@xdcr-.@items.wtavg_docs_latency": true,
                  "@xdcr-.@items.wtavg_meta_latency": true},
          size: "small",
          specificStat: false
        }, {
          stats: {"@xdcr-.@items.docs_failed_cr_source": true,
                  "@xdcr-.@items.docs_filtered": true},
          size: "small",
          specificStat: false
        }]
      }, {
        name: "vBucket Resources",
        isOpen: false,
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
                  "@kv-.vb_replica_ops_create": true,
                  "@kv-.vb_pending_ops_create": true,
                  "@kv-.ep_ops_create": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.vb_active_eject": true,
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
                  "@kv-.vb_replica_meta_data_memory": true,
                  "@kv-.vb_pending_meta_data_memory": true,
                  "@kv-.ep_meta_data_memory": true},
          size: "medium",
          specificStat: false
        }]
      }, {
        name: "DCP Queues",
        isOpen: false,
        charts: [{
          stats: {"@kv-.ep_dcp_views+indexes_count": true,
                  "@kv-.ep_dcp_cbas_count": true,
                  "@kv-.ep_dcp_replica_count": true,
                  "@kv-.ep_dcp_xdcr_count": true,
                  "@kv-.ep_dcp_eventing_count": true,
                  "@kv-.ep_dcp_other_count": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.ep_dcp_views+indexes_producer_count": true,
                  "@kv-.ep_dcp_cbas_producer_count": true,
                  "@kv-.ep_dcp_replica_producer_count": true,
                  "@kv-.ep_dcp_xdcr_producer_count": true,
                  "@kv-.ep_dcp_xdcr_eventing_count": true,
                  "@kv-.ep_dcp_other_producer_count": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.ep_dcp_views+indexes_items_remaining": true,
                  "@kv-.ep_dcp_cbas_items_remaining": true,
                  "@kv-.ep_dcp_replica_items_remaining": true,
                  "@kv-.ep_dcp_xdcr_items_remaining": true,
                  "@kv-.ep_dcp_eventing_items_remaining": true,
                  "@kv-.ep_dcp_other_items_remaining": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.ep_dcp_views+indexes_items_sent": true,
                  "@kv-.ep_dcp_cbas_items_sent": true,
                  "@kv-.ep_dcp_replica_items_sent": true,
                  "@kv-.ep_dcp_xdcr_items_sent": true,
                  "@kv-.ep_dcp_eventing_items_sent": true,
                  "@kv-.ep_dcp_other_items_sent": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.ep_dcp_views+indexes_total_bytes": true,
                  "@kv-.ep_dcp_cbas_total_bytes": true,
                  "@kv-.ep_dcp_replica_total_bytes": true,
                  "@kv-.ep_dcp_xdcr_total_bytes": true,
                  "@kv-.ep_dcp_eventing_total_bytes": true,
                  "@kv-.ep_dcp_other_total_bytes": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.ep_dcp_views+indexes_backoff": true,
                  "@kv-.ep_dcp_cbas_backoff": true,
                  "@kv-.ep_dcp_replica_backoff": true,
                  "@kv-.ep_dcp_xdcr_backoff": true,
                  "@kv-.ep_dcp_eventing_backoff": true,
                  "@kv-.ep_dcp_other_backoff": true},
          size: "medium",
          specificStat: false
        }
                ]
      }, {
        name: "Disk Queues",
        isOpen: false,
        charts: [{
          stats: {"@kv-.ep_diskqueue_fill": true,
                  "@kv-.ep_diskqueue_drain": true,
                  "@kv-.ep_diskqueue_items": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.vb_active_queue_fill": true,
                  "@kv-.vb_active_queue_drain": true,
                  "@kv-.vb_active_queue_size": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.vb_replica_queue_fill": true,
                  "@kv-.vb_replica_queue_drain": true,
                  "@kv-.vb_replica_queue_size": true},
          size: "medium",
          specificStat: false
        }, {
          stats: {"@kv-.vb_pending_queue_fill": true,
                  "@kv-.vb_pending_queue_drain": true,
                  "@kv-.vb_pending_queue_size": true},
          size: "medium",
          specificStat: false
        }
                ]
      }
              ]
    }]
  }
}
