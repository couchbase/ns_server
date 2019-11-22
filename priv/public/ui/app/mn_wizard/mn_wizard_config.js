import angular from "/ui/web_modules/angular.js";
import uiBootstrap from "/ui/web_modules/angular-ui-bootstrap.js";
import mnWizardService from "/ui/app/mn_wizard/mn_wizard_service.js";
import mnAlertsService from "/ui/app/components/mn_alerts.js";
import mnPromiseHelper from "/ui/app/components/mn_promise_helper.js";
import mnPools from "/ui/app/components/mn_pools.js";
import mnFilters from "/ui/app/components/mn_filters.js";
import mnStorageMode from "/ui/app/components/directives/mn_storage_mode/mn_storage_mode.js"
import mnHelper from "/ui/app/components/mn_helper.js";
import mnWizardWelcomeController from "/ui/app/mn_wizard/welcome/mn_wizard_welcome_controller.js";
import mnServersService from "/ui/app/mn_admin/mn_servers_service.js";
import mnAuthService from "/ui/app/mn_auth/mn_auth_service.js";
import mnSpinner from "/ui/app/components/directives/mn_spinner.js";
import mnFocus from "/ui/app/components/directives/mn_focus.js";
import mnMinlength from "/ui/app/components/directives/mn_validation/mn_minlength.js";
import mnEqual from "/ui/app/components/directives/mn_validation/mn_equal.js";
import mnAutocompleteOff from "/ui/app/components/directives/mn_autocomplete_off.js";
import mnServicesDiskPaths from "/ui/app/components/directives/mn_services_disk_paths.js";
import mnMemoryQuota from "/ui/app/components/directives/mn_memory_quota/mn_memory_quota.js";

import mnSettingsClusterService from "/ui/app/mn_admin/mn_settings_cluster_service.js";
import mnRootCertificateService from "/ui/app/mn_admin/mn_root_certificate_service.js";
import mnClusterConfigurationController from "/ui/app/mn_wizard/mn_cluster_configuration/mn_cluster_configuration_controller.js";
import mnTermsAndConditionsController from "/ui/app/mn_wizard/mn_terms_and_conditions/mn_terms_and_conditions_controller.js";
import mnClusterConfigurationService from "/ui/app/mn_wizard/mn_cluster_configuration/mn_cluster_configuration_service.js";
import mnSetupNewClusterController from "/ui/app/mn_wizard/mn_setup_new_cluster/mn_setup_new_cluster_controller.js";

export default 'mnWizard';

angular.module('mnWizard', [
  mnWizardService,
  mnClusterConfigurationService,
  mnAlertsService,
  mnSettingsClusterService,
  mnHelper,
  mnServersService,
  mnAuthService,
  mnSpinner,
  mnPromiseHelper,
  mnFocus,
  mnAutocompleteOff,
  mnStorageMode,
  mnMinlength,
  mnEqual,
  mnFilters,
  mnServicesDiskPaths,
  mnRootCertificateService,
  mnMemoryQuota,
  uiBootstrap
]).config(mnWizardConfig)
  .controller("mnClusterConfigurationController", mnClusterConfigurationController)
  .controller("mnTermsAndConditionsController", mnTermsAndConditionsController)
  .controller("mnSetupNewClusterController", mnSetupNewClusterController)
  .controller("mnWizardWelcomeController", mnWizardWelcomeController);

function mnWizardConfig($stateProvider) {
  $stateProvider
    .state('app.wizard', {
      abstract: true,
      templateUrl: 'app/mn_wizard/mn_wizard.html',
      controller: "mnWizardWelcomeController as wizardWelcomeCtl",
      resolve: {
        pools: function (mnPools) {
          return mnPools.get();
        }
      }
    })
    .state('app.wizard.welcome', {
      templateUrl: 'app/mn_wizard/welcome/mn_wizard_welcome.html'
    })
    .state('app.wizard.setupNewCluster', {
      templateUrl: 'app/mn_wizard/mn_setup_new_cluster/mn_setup_new_cluster.html',
      controller: 'mnSetupNewClusterController as setupNewClusterCtl'
    })
    .state('app.wizard.joinCluster', {
      templateUrl: 'app/mn_wizard/mn_join_cluster/mn_join_cluster.html',
      controller: 'mnClusterConfigurationController as clusterConfigurationCtl'
    })
    .state('app.wizard.termsAndConditions', {
      templateUrl: 'app/mn_wizard/mn_terms_and_conditions/mn_terms_and_conditions.html',
      controller: 'mnTermsAndConditionsController as termsCtl'
    })
    .state('app.wizard.clusterConfiguration', {
      templateUrl: 'app/mn_wizard/mn_cluster_configuration/mn_cluster_configuration.html',
      controller: 'mnClusterConfigurationController as clusterConfigurationCtl'
    })
}
