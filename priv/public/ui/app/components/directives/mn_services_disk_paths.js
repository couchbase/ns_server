(function () {
  "use strict";

  angular
    .module("mnServicesDiskPaths", ["mnClusterConfigurationService"])
    .directive("mnServicesDiskPaths", mnServicesDiskPathsDirective);

  function mnServicesDiskPathsDirective() {
    var mnServicesDiskPaths = {
      restrict: "AE",
      scope: {
        config: "=",
        postDiskStorageErrors: "=",
        isEnterprise: "=",
        isDisabled: "=?"
      },
      templateUrl: "app/components/directives/mn_services_disk_paths.html",
      controller: controller,
      controllerAs: "mnCtl"
    };

    return mnServicesDiskPaths;

    function controller($scope, mnClusterConfigurationService) {
      var vm = this;
      vm.onDbPathChange = onDbPathChange;
      vm.onIndexPathChange = onIndexPathChange;
      vm.onCbasDirsChange = onCbasDirsChange;
      vm.addCbasPath = addCbasPath;

      activate();

      function activate() {
        vm.onDbPathChange();
        vm.onIndexPathChange();
        if ($scope.config.cbasDirs) {
          $scope.config.cbasDirs.forEach(function (path, index) {
            vm.onCbasDirsChange(index);
          });
        }
      }

      function onDbPathChange() {
        vm.dbPathTotal =
          mnClusterConfigurationService.lookup(
            $scope.config.dbPath,
            $scope.config.selfConfig.preprocessedAvailableStorage);
      }
      function onIndexPathChange() {
        vm.indexPathTotal =
          mnClusterConfigurationService.lookup(
            $scope.config.indexPath,
            $scope.config.selfConfig.preprocessedAvailableStorage);
      }
      function onCbasDirsChange(index) {
        vm["cbasDirsTotal" + index] =
          mnClusterConfigurationService.lookup(
            $scope.config.cbasDirs[index],
            $scope.config.selfConfig.preprocessedAvailableStorage);
      }
      function addCbasPath() {
        var last = $scope.config.cbasDirs.length-1;
        vm["cbasDirsTotal" + (last + 1)] = vm["cbasDirsTotal" + last];
        $scope.config.cbasDirs.push($scope.config.cbasDirs[last]);
      }
    }

  }
})();
