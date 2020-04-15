import {format} from "/ui/web_modules/d3-format.js";

export default mnFooterStatsController;

function mnFooterStatsController($scope, mnStatisticsNewService, mnPermissions) {
  var vm = this;
  vm.currentBucket = mnPermissions.export.bucketNames['.stats!read'] &&
    mnPermissions.export.bucketNames['.stats!read'][0];
  vm.onSelectBucket = onSelectBucket;

  vm.getLatestStat = getLatestStat;
  vm.getLatestStatExponent = getLatestStatExponent;

  var config = {
    bucket: vm.currentBucket,
    node: "all",
    zoom: 3000,
    step: 1,
    stats: $scope.stats
  };

  activate();

  function activate() {
    mnStatisticsNewService.subscribeUIStatsPoller(config, $scope);
  }

  function getLatestStat(statName) {
    return $scope.mnUIStats &&
      $scope.mnUIStats.stats[statName] &&
      $scope.mnUIStats.stats[statName].aggregate.slice().reverse().find(stat => stat != null);
  }

  function getLatestStatExponent(statName, digits) {
    var value = getLatestStat(statName);
    if (value) {
      return(format('.'+digits+'e')(value));
    } else {
      return value;
    }
  }

  function onSelectBucket() {
    config.bucket = vm.currentBucket;
    mnStatisticsNewService.heartbeat.throttledReload();
  }

}
