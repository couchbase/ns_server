export default mnAnalyticsListController;

function mnAnalyticsListController(mnHelper, $state) {
  var vm = this;
  vm.params = $state.params;
  var expanderStateParamName = $state.params.specificStat ? 'openedSpecificStatsBlock' : 'openedStatsBlock';
  mnHelper.initializeDetailsHashObserver(vm, expanderStateParamName, $state.params.specificStat ? '^.specificGraph' : '^.graph');
}
